/**
 * The "legacy" stack: RSA, AES-256-GCM, salted SHA-256 passwords and
 * HMAC-SHA256 tokens. Each is secure only because some problem is assumed hard.
 *
 * SCALED DOWN ON PURPOSE: the RSA modulus is 64 bits and the HMAC key has
 * 20 unknown bits, so the brute-force stand-in for a P = NP solver finishes in
 * seconds. A real polynomial-time solver would break the full-size versions
 * the same way. Salted SHA-256 passwords are left at full strength: guessable
 * passwords fall to search even today.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes as nodeRandom } from "node:crypto";

export const RSA_BITS = 64;
export const HMAC_UNKNOWN_BITS = 20;

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  base %= m;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return r;
}

export function modInverse(a: bigint, m: bigint): bigint {
  let r0 = ((a % m) + m) % m;
  let r1 = m;
  let s0 = 1n;
  let s1 = 0n;
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new RangeError("not invertible");
  return ((s0 % m) + m) % m;
}

export function isProbablePrime(n: bigint): boolean {
  if (n < 2n) return false;
  const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  for (const p of bases) if (n % p === 0n) return n === p;
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  outer: for (const a of bases) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue outer;
    }
    return false;
  }
  return true; // deterministic for n < 3.3e24
}

function randomPrime(bits: number): bigint {
  for (;;) {
    let x = BigInt("0x" + nodeRandom(Math.ceil(bits / 8)).toString("hex"));
    x &= (1n << BigInt(bits)) - 1n;
    x |= (1n << BigInt(bits - 1)) | 1n;
    if (isProbablePrime(x)) return x;
  }
}

export interface RsaPublic {
  n: bigint;
  e: bigint;
}
export interface RsaPrivate extends RsaPublic {
  d: bigint;
}

export function generateRsa(bits = RSA_BITS): RsaPrivate {
  const e = 65537n;
  for (;;) {
    const p = randomPrime(bits / 2);
    const q = randomPrime(bits / 2);
    if (p === q) continue;
    try {
      return { n: p * q, e, d: modInverse(e, (p - 1n) * (q - 1n)) };
    } catch {
      continue;
    }
  }
}

/** RSA over arbitrary bytes: 6-byte chunks, each with a random pad byte on top. */
const RSA_CHUNK = 6;

export function rsaEncryptBytes(pub: RsaPublic, data: Uint8Array): string[] {
  const out: string[] = [];
  for (let i = 0; i < data.length; i += RSA_CHUNK) {
    const hex = Buffer.from(data.subarray(i, i + RSA_CHUNK)).toString("hex").padEnd(RSA_CHUNK * 2, "0");
    const m = (BigInt(nodeRandom(1)[0]!) << 48n) | BigInt("0x" + hex);
    out.push(modPow(m, pub.e, pub.n).toString());
  }
  return out;
}

export function rsaDecryptBytes(priv: RsaPrivate, chunks: string[], length: number): Uint8Array {
  const out = Buffer.alloc(chunks.length * RSA_CHUNK);
  chunks.forEach((c, i) => {
    const m = modPow(BigInt(c), priv.d, priv.n) & ((1n << 48n) - 1n);
    Buffer.from(m.toString(16).padStart(12, "0"), "hex").copy(out, i * RSA_CHUNK);
  });
  return new Uint8Array(out.subarray(0, length));
}

function digest(msg: string, n: bigint): bigint {
  return BigInt("0x" + createHash("sha256").update(msg).digest("hex")) % n;
}

export function rsaSign(priv: RsaPrivate, msg: string): string {
  return modPow(digest(msg, priv.n), priv.d, priv.n).toString();
}

export function rsaVerify(pub: RsaPublic, msg: string, sig: string): boolean {
  return modPow(BigInt(sig), pub.e, pub.n) === digest(msg, pub.n);
}

export interface GcmBox {
  iv: string;
  ct: string;
  tag: string;
}

export function aesGcmEncrypt(key: Uint8Array, plaintext: string): GcmBox {
  const iv = nodeRandom(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return { iv: iv.toString("hex"), ct: ct.toString("hex"), tag: c.getAuthTag().toString("hex") };
}

export function aesGcmDecrypt(key: Uint8Array, box: GcmBox): string {
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "hex"));
  d.setAuthTag(Buffer.from(box.tag, "hex"));
  return Buffer.concat([d.update(Buffer.from(box.ct, "hex")), d.final()]).toString("utf8");
}

export function sha256Password(salt: string, password: string): string {
  return createHash("sha256").update(salt + password).digest("hex");
}

/** A 32-byte HMAC key with 20 random bits and the rest zero (scaled down). */
export function weakHmacKey(): Buffer {
  const key = Buffer.alloc(32);
  const r = nodeRandom(3);
  key[0] = r[0]!;
  key[1] = r[1]!;
  key[2] = r[2]! & 0xf0;
  return key;
}

export function hmacToken(key: Uint8Array, payload: object): string {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${createHmac("sha256", key).update(body).digest("hex")}`;
}

export function verifyHmacToken(key: Uint8Array, token: string): Record<string, unknown> | null {
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  if (createHmac("sha256", key).update(body).digest("hex") !== mac) return null;
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
}
