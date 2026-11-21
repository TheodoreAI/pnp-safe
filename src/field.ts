/**
 * Arithmetic modulo the Mersenne prime 2^127 - 1, plus the byte helpers
 * shared by the MAC and the password hasher.
 */

/** The field modulus: 2^127 - 1. */
export const P127 = (1n << 127n) - 1n;

/** Number of message bytes packed into one field element. 15 bytes < 2^127. */
export const CHUNK_BYTES = 15;

export function mod(x: bigint): bigint {
  const r = x % P127;
  return r < 0n ? r + P127 : r;
}

export function addMod(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function mulMod(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

export function bytesToBigint(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}

/** Reads exactly 16 bytes as a field element, masked to 127 bits. */
export function bytesToField(bytes: Uint8Array): bigint {
  if (bytes.length !== 16) throw new RangeError("bytesToField needs exactly 16 bytes");
  return mod(bytesToBigint(bytes) & P127);
}

/** Writes a field element as 16 big-endian bytes. */
export function fieldToBytes(x: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let v = mod(x);
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Injective encoding of a byte string into field elements: 15-byte chunks
 * followed by one element holding the byte length. Two different messages
 * never produce the same sequence, and the length element makes sequences of
 * different lengths differ in their final position.
 */
export function encodeMessage(msg: Uint8Array): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < msg.length; i += CHUNK_BYTES) {
    out.push(bytesToBigint(msg.subarray(i, i + CHUNK_BYTES)));
  }
  out.push(BigInt(msg.length));
  return out;
}

/** Evaluates sum(m_i * a^(L-i)) by Horner's rule: the polynomial universal hash. */
export function polyHash(a: bigint, elements: bigint[]): bigint {
  let h = 0n;
  for (const m of elements) h = mod((h + m) * a);
  return h;
}

/** Compares two byte arrays without returning early on the first difference. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
