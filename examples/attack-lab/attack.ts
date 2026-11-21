/**
 * The adversary. It taps the network, steals the database, and has a P = NP
 * oracle. Against the legacy vault it uses the oracle directly. Against
 * pnp-safe it does the strongest thing unlimited computation allows: it
 * enumerates or constructs EVERY key consistent with what it saw, and shows
 * that the evidence fits contradictory answers equally well.
 */
import {
  InMemoryPepperStore,
  P127,
  PasswordHasher,
  bytesToField,
  combine,
  concatBytes,
  decodeSealed,
  encodeMessage,
  encodeSealed,
  fieldToBytes,
  fromBase64,
  gfDiv,
  gfMul,
  mod,
  polyHash,
  polyMac,
  toBase64,
  xor,
  type PasswordRecord,
  type Sealed,
  type Share,
} from "../../src/index.js";
import { api, USERS } from "./client.js";
import { HMAC_UNKNOWN_BITS, aesGcmDecrypt, hmacToken, modInverse, modPow, rsaDecryptBytes, rsaSign } from "./legacy.js";
import { PnpOracle } from "./oracle.js";
import type { WireEntry } from "./server.js";

export type Outcome = "BROKEN" | "HELD" | "BROKEN (out of model)";

export interface Finding {
  side: "legacy" | "pnp-safe";
  target: string;
  attack: string;
  outcome: Outcome;
  evidence: string;
  ms: number;
}

const DICTIONARY = ["123456", "password", "qwerty", "letmein", "dragon", "sunshine", "monkey", "iloveyou"];
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const enc = new TextEncoder();
const dec = new TextDecoder();

async function timed(f: Omit<Finding, "ms" | "outcome" | "evidence">, run: () => Promise<[Outcome, string]>): Promise<Finding> {
  const t = performance.now();
  try {
    const [outcome, evidence] = await run();
    return { ...f, outcome, evidence, ms: Math.round(performance.now() - t) };
  } catch (e) {
    return { ...f, outcome: "HELD", evidence: `attack code failed: ${String(e)}`, ms: Math.round(performance.now() - t) };
  }
}

/** The 12-byte header pnp-safe authenticates along with the ciphertext. */
function macInput(s: Sealed): Uint8Array {
  const h = new Uint8Array(12);
  const v = new DataView(h.buffer);
  v.setBigUint64(0, BigInt(s.offset));
  v.setUint32(8, s.ciphertext.length);
  return concatBytes(h, s.ciphertext);
}

/** A random nonzero field element. Any source works: the attacker is free to pick. */
function anyFieldElement(): bigint {
  for (;;) {
    const x = bytesToField(crypto.getRandomValues(new Uint8Array(16)));
    if (x !== 0n) return x;
  }
}

/** Coefficients (lowest degree first) of the polynomial through the points, over GF(2^127 - 1). */
function interpolate(xs: bigint[], ys: bigint[]): bigint[] {
  let result: bigint[] = [0n];
  for (let i = 0; i < xs.length; i++) {
    let num: bigint[] = [1n];
    let denom = 1n;
    for (let j = 0; j < xs.length; j++) {
      if (j === i) continue;
      const next = new Array<bigint>(num.length + 1).fill(0n);
      num.forEach((c, k) => {
        next[k + 1] = mod(next[k + 1]! + c);
        next[k] = mod(next[k]! - c * xs[j]!);
      });
      num = next;
      denom = mod(denom * (xs[i]! - xs[j]!));
    }
    const scale = mod(ys[i]! * modPow(denom, P127 - 2n, P127));
    const sum = new Array<bigint>(Math.max(result.length, num.length)).fill(0n);
    result.forEach((c, k) => (sum[k] = c));
    num.forEach((c, k) => (sum[k] = mod(sum[k]! + c * scale)));
    result = sum;
  }
  return result;
}

/**
 * Builds a pepper under which the stolen records verify against the given
 * guesses. Possible for ANY guesses while there are fewer than t records.
 */
function pepperExplaining(records: PasswordRecord[], guesses: string[], t: number): Uint8Array {
  const a = anyFieldElement();
  const xs = records.map((r, i) =>
    polyHash(a, encodeMessage(concatBytes(fromBase64(r.salt), enc.encode(guesses[i]!.normalize("NFC"))))),
  );
  const ys = records.map((r) => bytesToField(fromBase64(r.tag)));
  const low = interpolate(xs, ys);
  const coeffs = new Array<bigint>(t).fill(0n);
  low.forEach((c, k) => (coeffs[k] = c));
  coeffs.reverse(); // the store evaluates highest degree first
  return concatBytes(fieldToBytes(a), ...coeffs.map(fieldToBytes));
}

/** GF(256) Lagrange evaluation at X through the given points. */
function gfEval(points: [number, number][], X: number): number {
  let acc = 0;
  for (const [xi, yi] of points) {
    let l = 1;
    for (const [xj] of points) if (xj !== xi) l = gfMul(l, gfDiv(X ^ xj, xi ^ xj));
    acc ^= gfMul(yi, l);
  }
  return acc;
}

/** A fake share at x that, combined with the stolen ones, yields `decoy`. */
function fabricateShare(stolen: Share[], decoy: Uint8Array, x: number): Share {
  const y = new Uint8Array(decoy.length);
  for (let b = 0; b < decoy.length; b++) {
    y[b] = gfEval([[0, decoy[b]!], ...stolen.map((s): [number, number] => [s.x, s.y[b]!])], x);
  }
  return { x, y };
}

export async function runAttacks(base: string, oracle = new PnpOracle()): Promise<Finding[]> {
  const findings: Finding[] = [];
  const wire = (await api(base, "GET", "/breach/wire")).json as WireEntry[];
  const db = (await api(base, "GET", "/breach/db")).json;
  const truth = (await api(base, "GET", "/lab/truth")).json; // grading only

  // ================= LEGACY =================
  const pub = (await api(base, "GET", "/legacy/pubkey")).json;
  const n = BigInt(pub.n);
  const e = BigInt(pub.e);
  const [p, q] = oracle.factor(n);
  const priv = { n, e, d: modInverse(e, (p - 1n) * (q - 1n)) };

  findings.push(
    await timed({ side: "legacy", target: "RSA + AES-256-GCM", attack: "Wiretap, factor the RSA modulus, unwrap the AES key, decrypt" }, async () => {
      const msg = wire.find((w) => w.channel === "legacy" && w.kind === "message")!.data as any;
      const pt = aesGcmDecrypt(rsaDecryptBytes(priv, msg.encKey, 32), msg.box);
      const ok = pt === truth.legacyInbox[0];
      return [ok ? "BROKEN" : "HELD", `n = ${p} x ${q}; recovered "${pt}"`];
    }),
  );

  findings.push(
    await timed({ side: "legacy", target: "RSA signatures", attack: "Forge the bank's signature with the recovered private key" }, async () => {
      const text = "Bank authorizes transfer of $1,000,000 to mallory";
      const r = await api(base, "POST", "/legacy/verify", { text, sig: rsaSign(priv, text) });
      return [r.json.valid ? "BROKEN" : "HELD", `server says signature on "${text}" is ${r.json.valid ? "valid" : "invalid"}`];
    }),
  );

  findings.push(
    await timed({ side: "legacy", target: "Salted SHA-256 passwords", attack: "Steal the user table, invert each hash, log in" }, async () => {
      const cracked: string[] = [];
      for (const [user, rec] of Object.entries(db.legacyUsers as Record<string, { salt: string; hash: string }>)) {
        const pw = oracle.invertPasswordHash(rec.salt, rec.hash, DICTIONARY, ALPHABET, 3);
        if (pw && (await api(base, "POST", "/legacy/login", { user, password: pw })).status === 200) cracked.push(`${user}:${pw}`);
      }
      const all = cracked.length === Object.keys(USERS).length;
      return [all ? "BROKEN" : "HELD", `cracked and logged in as ${cracked.join(", ") || "nobody"}`];
    }),
  );

  findings.push(
    await timed({ side: "legacy", target: "HMAC-SHA256 session tokens", attack: "Recover the server's HMAC key from one token, mint an admin token" }, async () => {
      await api(base, "POST", "/legacy/register", { user: "mallory", password: "mallory-pw" });
      const token = (await api(base, "POST", "/legacy/login", { user: "mallory", password: "mallory-pw" })).json.token as string;
      const [body, mac] = token.split(".") as [string, string];
      const key = oracle.recoverHmacKey([{ body, mac }], HMAC_UNKNOWN_BITS);
      if (!key) return ["HELD", "no consistent key found"];
      const r = await api(base, "POST", "/legacy/admin", { token: hmacToken(key, { user: "mallory", role: "admin" }) });
      return [r.status === 200 ? "BROKEN" : "HELD", `forged admin token -> HTTP ${r.status} ${JSON.stringify(r.json)}`];
    }),
  );

  // ================= PNP-SAFE =================
  const pnpWire = wire.filter((w) => w.channel === "pnp" && w.kind === "message");
  const delivered = decodeSealed(fromBase64(String(pnpWire.find((w) => w.delivered)!.data.sealed)));
  const inFlight = decodeSealed(fromBase64(String(pnpWire.find((w) => !w.delivered)!.data.sealed)));

  findings.push(
    await timed({ side: "pnp-safe", target: "One-time pad confidentiality", attack: "Wiretap and search every key for the plaintext" }, async () => {
      const c = delivered.ciphertext;
      const L = c.length;
      // Exhaustive search over the first two key bytes: every prefix appears exactly once.
      const prefixes = new Set<number>();
      for (let k = 0; k < 65536; k++) prefixes.add(((c[0]! ^ (k >> 8)) << 8) | (c[1]! ^ (k & 0xff)));
      // Contradictory full messages: each has exactly one key that produces it.
      const fit = (s: string) => enc.encode(s.padEnd(L, ".").slice(0, L));
      const candidates = ["Wire $25,000 to account 4471 on Friday", "Wire $99,999 to account 6666 on Monday", "Ignore all previous wire instructions!"];
      const allFit = candidates.every((s) => {
        const key = xor(c, fit(s));
        return dec.decode(xor(c, key)) === dec.decode(fit(s));
      });
      const held = prefixes.size === 65536 && allFit;
      return [
        held ? "HELD" : "BROKEN",
        `all ${prefixes.size} two-byte prefixes equally likely; ${candidates.length} contradictory ${L}-byte messages each fit exactly one key. Only the length leaks.`,
      ];
    }),
  );

  findings.push(
    await timed({ side: "pnp-safe", target: "One-time MAC integrity", attack: "Intercept an in-flight message, change $25,000 to $99,999, re-tag with keys consistent with an observed tag" }, async () => {
      // Known-plaintext bit flip: the classic attack on a bare one-time pad.
      const known = enc.encode("Wire $25,000 to account 4471 on Monday");
      const wanted = enc.encode("Wire $99,999 to account 6666 on Monday");
      const flipped: Sealed = { ...inFlight, ciphertext: xor(inFlight.ciphertext, xor(known, wanted)) };
      // The oracle's best tag guesses: keys (a, b) that reproduce the tag it saw on the delivered message.
      const observed = macInput(delivered);
      const observedTag = bytesToField(delivered.tag);
      const guesses: Uint8Array[] = [inFlight.tag];
      for (let i = 0; i < 3; i++) {
        const a = anyFieldElement();
        const b = mod(observedTag - polyHash(a, encodeMessage(observed)));
        const key = concatBytes(fieldToBytes(a), fieldToBytes(b));
        if (toBase64(polyMac(key, observed)) !== toBase64(delivered.tag)) throw new Error("consistent-key construction failed");
        guesses.push(polyMac(key, macInput(flipped)));
      }
      for (let i = 0; i < 200; i++) guesses.push(crypto.getRandomValues(new Uint8Array(16)));
      const statuses = new Map<number, number>();
      for (const tag of guesses) {
        const r = await api(base, "POST", "/pnp/send", { sealed: toBase64(encodeSealed({ ...flipped, tag })) });
        statuses.set(r.status, (statuses.get(r.status) ?? 0) + 1);
      }
      const accepted = statuses.get(202) ?? 0;
      return [
        accepted === 0 ? "HELD" : "BROKEN",
        `${guesses.length} forgeries (original tag, 3 tags from keys that fit the observed tag, 200 random): ${accepted} accepted, responses ${JSON.stringify(Object.fromEntries(statuses))}`,
      ];
    }),
  );

  findings.push(
    await timed({ side: "pnp-safe", target: "Replay protection", attack: "Resend the captured, already-delivered message" }, async () => {
      const r = await api(base, "POST", "/pnp/send", { sealed: toBase64(encodeSealed(delivered)) });
      return [r.status === 202 ? "BROKEN" : "HELD", `server answered HTTP ${r.status}: ${r.json.error ?? "accepted"}`];
    }),
  );

  findings.push(
    await timed({ side: "pnp-safe", target: "Pad exhaustion (denial of service)", attack: "Send a forgery far ahead in the pad to make the server skip and burn key bytes" }, async () => {
      const r = await api(base, "POST", "/pnp/send", {
        sealed: toBase64(encodeSealed({ offset: 7000, ciphertext: new Uint8Array(40), tag: new Uint8Array(16) })),
      });
      return [r.status === 202 ? "BROKEN" : "HELD", `forgery answered HTTP ${r.status}; pad survival is checked when the real message arrives`];
    }),
  );

  findings.push(
    await timed({ side: "pnp-safe", target: "Peppered password tags", attack: "Steal the user table (no pepper) and test guesses offline" }, async () => {
      const users = Object.keys(db.pnpUsers);
      const records = users.map((u) => db.pnpUsers[u] as PasswordRecord);
      const t = db.pnpIndependence as number;
      if (records.length >= t) {
        return ["BROKEN", `${records.length} records but only ${t}-wise independence: the guarantee no longer applies`];
      }
      const scenarios: Record<string, string[]> = {
        "true passwords": users.map((u) => USERS[u as keyof typeof USERS]),
        "wrong guesses": users.map((u) => `definitely-not-${u}`),
        "dictionary words": users.map((_, i) => DICTIONARY[i]!),
      };
      const fits: string[] = [];
      for (const [name, guesses] of Object.entries(scenarios)) {
        const hasher = new PasswordHasher(new InMemoryPepperStore(pepperExplaining(records, guesses, t)));
        const ok = (await Promise.all(records.map((r, i) => hasher.verify(guesses[i]!, r)))).every(Boolean);
        if (ok) fits.push(name);
      }
      const held = fits.length === Object.keys(scenarios).length;
      return [
        held ? "HELD" : "BROKEN",
        `built a pepper that makes the stolen table verify for each of: ${fits.join("; ")}. With ${records.length} of ${t} records the table cannot tell them apart.`,
      ];
    }),
  );

  findings.push(
    await timed({ side: "pnp-safe", target: "Shamir 3-of-5 backup", attack: "Steal 2 shares and solve for the master key" }, async () => {
      const stolen: Share[] = (db.backupShares as { x: number; y: string }[]).map((s) => ({ x: s.x, y: fromBase64(s.y) }));
      const len = stolen[0]!.y.length;
      let consistent = 0;
      for (let v = 0; v < 256; v++) {
        const decoy = new Uint8Array(len);
        decoy[0] = v;
        if (combine([...stolen, fabricateShare(stolen, decoy, 200)])[0] === v) consistent++;
      }
      const decoy = enc.encode("this is not the key, honestly!!".padEnd(len, "!").slice(0, len));
      const fake = dec.decode(combine([...stolen, fabricateShare(stolen, decoy, 200)]));
      const held = consistent === 256;
      return [held ? "HELD" : "BROKEN", `all ${consistent} values of the first byte fit the 2 shares; a fabricated third share yields "${fake}" just as validly`];
    }),
  );

  findings.push(
    await timed({ side: "pnp-safe", target: "Peppered password tags", attack: "OUT OF MODEL: steal the pepper too, then guess offline" }, async () => {
      const hasher = new PasswordHasher(new InMemoryPepperStore(fromBase64((await api(base, "GET", "/breach/pepper")).json.pepper)));
      const cracked: string[] = [];
      for (const [user, rec] of Object.entries(db.pnpUsers as Record<string, PasswordRecord>)) {
        const tryPw = async (pw: string) => ((await hasher.verify(pw, rec)) ? pw : null);
        let found: string | null = null;
        for (const w of DICTIONARY) if (!found) found = await tryPw(w);
        const search = async (prefix: string): Promise<string | null> => {
          if (prefix && (await tryPw(prefix))) return prefix;
          if (prefix.length === 3) return null;
          for (const ch of ALPHABET) {
            const r = await search(prefix + ch);
            if (r) return r;
          }
          return null;
        };
        found ??= await search("");
        if (found) cracked.push(`${user}:${found}`);
      }
      return [
        cracked.length ? "BROKEN (out of model)" : "HELD",
        `with the pepper leaked, weak passwords fall to guessing: ${cracked.join(", ") || "none"}. The README documents this.`,
      ];
    }),
  );

  return findings;
}
