/**
 * Attack-lab server. Runs two vaults side by side:
 *   /legacy/*  RSA + AES-256-GCM + salted SHA-256 + HMAC tokens
 *   /pnp/*     pnp-safe: pad channel + one-time MAC, peppered passwords, Shamir backup
 * plus simulated breach endpoints (/breach/*) that hand an attacker the network
 * tap, the database, and in one out-of-model test the pepper.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { randomBytes as nodeRandom } from "node:crypto";
import {
  AuthenticationError,
  InMemoryPepperStore,
  KeyPad,
  KeyReuseError,
  KeyExhaustedError,
  PasswordHasher,
  SecureChannel,
  bytesToField,
  decodeSealed,
  fromBase64,
  randomBytes,
  split,
  toBase64,
  type PasswordRecord,
  type Share,
} from "../../src/index.js";
import {
  aesGcmDecrypt,
  generateRsa,
  hmacToken,
  rsaDecryptBytes,
  rsaSign,
  rsaVerify,
  sha256Password,
  verifyHmacToken,
  weakHmacKey,
  type GcmBox,
  type RsaPrivate,
} from "./legacy.js";

export const PNP_INDEPENDENCE = 64;
export const PAD_BYTES = 8192;

export interface WireEntry {
  id: number;
  channel: "legacy" | "pnp";
  kind: string;
  delivered: boolean;
  data: Record<string, unknown>;
}

class LabState {
  readonly rsa: RsaPrivate = generateRsa();
  readonly hmacKey = weakHmacKey();
  readonly legacyUsers = new Map<string, { salt: string; hash: string }>();
  readonly legacyInbox: string[] = [];

  readonly pepperKey: Uint8Array;
  readonly hasher: PasswordHasher;
  readonly pnpUsers = new Map<string, PasswordRecord>();
  readonly padMaterial: Uint8Array;
  readonly channel: SecureChannel;
  readonly pnpInbox: string[] = [];
  readonly backupSecret = new TextEncoder().encode("vault master key 7f3a-91c2-d4e8");
  readonly shares: Share[];

  readonly wire: WireEntry[] = [];

  constructor() {
    // Pepper: 16 * (t + 1) bytes of extracted entropy; the hash key must be nonzero.
    let key: Uint8Array;
    do key = randomBytes(InMemoryPepperStore.keyBytes(PNP_INDEPENDENCE));
    while (bytesToField(key.subarray(0, 16)) === 0n);
    this.pepperKey = key;
    this.hasher = new PasswordHasher(new InMemoryPepperStore(key));
    this.padMaterial = randomBytes(PAD_BYTES);
    this.channel = new SecureChannel(new KeyPad(this.padMaterial));
    this.shares = split(this.backupSecret, 5, 3);
  }

  log(channel: WireEntry["channel"], kind: string, data: Record<string, unknown>, delivered = true): WireEntry {
    const e = { id: this.wire.length + 1, channel, kind, delivered, data };
    this.wire.push(e);
    return e;
  }
}

type Json = Record<string, unknown>;
type Handler = (s: LabState, body: Json) => Promise<[number, unknown]> | [number, unknown];

const routes: Record<string, Handler> = {
  // ---- legacy vault ----
  "GET /legacy/pubkey": (s) => [200, { n: s.rsa.n.toString(), e: s.rsa.e.toString() }],
  "POST /legacy/register": (s, b) => {
    const salt = nodeRandom(16).toString("hex");
    s.legacyUsers.set(String(b.user), { salt, hash: sha256Password(salt, String(b.password)) });
    return [201, { ok: true }];
  },
  "POST /legacy/login": (s, b) => {
    const u = s.legacyUsers.get(String(b.user));
    if (!u || sha256Password(u.salt, String(b.password)) !== u.hash) return [401, { error: "bad credentials" }];
    return [200, { token: hmacToken(s.hmacKey, { user: b.user, role: "user" }) }];
  },
  "POST /legacy/admin": (s, b) => {
    const claims = verifyHmacToken(s.hmacKey, String(b.token));
    if (!claims) return [401, { error: "bad token" }];
    if (claims.role !== "admin") return [403, { error: "admins only" }];
    return [200, { panel: "admin panel unlocked", user: claims.user }];
  },
  "POST /legacy/send": (s, b) => {
    s.log("legacy", "message", b);
    const aesKey = rsaDecryptBytes(s.rsa, b.encKey as string[], 32);
    s.legacyInbox.push(aesGcmDecrypt(aesKey, b.box as GcmBox));
    return [202, { ok: true }];
  },
  "GET /legacy/statement": (s) => {
    const text = "Statement: alice balance $1,204.17";
    return [200, { text, sig: rsaSign(s.rsa, text) }];
  },
  "POST /legacy/verify": (s, b) => [200, { valid: rsaVerify(s.rsa, String(b.text), String(b.sig)) }],

  // ---- pnp-safe vault ----
  "POST /pnp/register": async (s, b) => {
    s.pnpUsers.set(String(b.user), await s.hasher.hash(String(b.password)));
    return [201, { ok: true }];
  },
  "POST /pnp/login": async (s, b) => {
    const rec = s.pnpUsers.get(String(b.user));
    return rec && (await s.hasher.verify(String(b.password), rec)) ? [200, { ok: true }] : [401, { error: "bad credentials" }];
  },
  "POST /pnp/send": (s, b) => {
    s.log("pnp", "message", b);
    try {
      s.pnpInbox.push(new TextDecoder().decode(s.channel.open(decodeSealed(fromBase64(String(b.sealed))))));
      return [202, { ok: true }];
    } catch (e) {
      if (e instanceof AuthenticationError) return [401, { error: e.message }];
      if (e instanceof KeyReuseError) return [409, { error: e.message }];
      if (e instanceof KeyExhaustedError) return [400, { error: e.message }];
      return [400, { error: String(e) }];
    }
  },

  // ---- the network: a message the client has sent that has not arrived yet ----
  "POST /net/inflight": (s, b) => [202, { id: s.log("pnp", "message", b, false).id }],

  // ---- simulated breaches ----
  "GET /breach/wire": (s) => [200, s.wire],
  "GET /breach/db": (s) => [
    200,
    {
      legacyUsers: Object.fromEntries(s.legacyUsers),
      pnpUsers: Object.fromEntries(s.pnpUsers),
      pnpIndependence: PNP_INDEPENDENCE,
      backupShares: s.shares.slice(0, 2).map((sh) => ({ x: sh.x, y: toBase64(sh.y) })),
      backupThreshold: 3,
    },
  ],
  "GET /breach/pepper": (s) => [200, { pepper: toBase64(s.pepperKey) }],

  // ---- grading only; the attacker never calls this ----
  "GET /lab/truth": (s) => [200, { legacyInbox: s.legacyInbox, pnpInbox: s.pnpInbox }],
};

export interface Lab {
  url: string;
  state(): LabState;
  /** The out-of-band copy of the pad, as if delivered in person. */
  clientPad(): KeyPad;
  reset(): void;
  close(): Promise<void>;
  onAttack?: () => Promise<unknown>;
  lastReport?: unknown;
}

async function readBody(req: IncomingMessage): Promise<Json> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? (JSON.parse(raw) as Json) : {};
}

function send(res: ServerResponse, status: number, body: unknown, type = "application/json"): void {
  res.writeHead(status, { "content-type": type });
  res.end(type === "application/json" ? JSON.stringify(body) : String(body));
}

export async function startLab(port: number, publicDir: string): Promise<Lab> {
  let state = new LabState();
  const lab: Lab = {
    url: "",
    state: () => state,
    clientPad: () => new KeyPad(state.padMaterial),
    reset: () => {
      state = new LabState();
    },
    close: () => new Promise((r) => server.close(() => r())),
  };
  const server = createServer(async (req, res) => {
    const path = (req.url ?? "/").split("?")[0]!;
    try {
      if (req.method === "GET" && path === "/") {
        return send(res, 200, await readFile(`${publicDir}/index.html`, "utf8"), "text/html; charset=utf-8");
      }
      if (req.method === "GET" && path === "/api/report") return send(res, lab.lastReport ? 200 : 404, lab.lastReport ?? {});
      if (req.method === "POST" && path === "/api/attack" && lab.onAttack) return send(res, 200, await lab.onAttack());
      const handler = routes[`${req.method} ${path}`];
      if (!handler) return send(res, 404, { error: "not found" });
      const [status, body] = await handler(state, await readBody(req));
      send(res, status, body);
    } catch (e) {
      send(res, 500, { error: String(e) });
    }
  });
  await new Promise<void>((r) => server.listen(port, "127.0.0.1", () => r()));
  const addr = server.address();
  lab.url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : port}`;
  return lab;
}
