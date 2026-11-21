/**
 * Shamir secret sharing over GF(256), byte by byte. Any k shares rebuild the
 * secret; any k - 1 shares are statistically independent of it.
 */
import { randomBytes, type EntropySource } from "./entropy.js";

export interface Share {
  /** Evaluation point, 1 to 255. */
  x: number;
  y: Uint8Array;
}

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  // Generator 3 over the AES polynomial x^8 + x^4 + x^3 + x + 1.
  let v = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = v;
    LOG[v] = i;
    v ^= (v << 1) ^ (v & 0x80 ? 0x11b : 0);
    v &= 0xff;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
}

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a]! + LOG[b]!]!;
}

export function gfDiv(a: number, b: number): number {
  if (b === 0) throw new RangeError("division by zero in GF(256)");
  if (a === 0) return 0;
  return EXP[LOG[a]! + 255 - LOG[b]!]!;
}

export function split(secret: Uint8Array, n: number, k: number, source?: EntropySource): Share[] {
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 2 || n < k || n > 255) {
    throw new RangeError("need 2 <= k <= n <= 255");
  }
  const coeffs = randomBytes(secret.length * (k - 1), source);
  const shares: Share[] = [];
  for (let x = 1; x <= n; x++) {
    const y = new Uint8Array(secret.length);
    for (let i = 0; i < secret.length; i++) {
      // Horner: highest coefficient first, the secret byte is the constant term.
      let acc = 0;
      for (let d = k - 2; d >= 0; d--) acc = gfMul(acc, x) ^ coeffs[i * (k - 1) + d]!;
      y[i] = gfMul(acc, x) ^ secret[i]!;
    }
    shares.push({ x, y });
  }
  coeffs.fill(0);
  return shares;
}

/**
 * Lagrange interpolation at zero. Passing fewer than k shares returns a wrong
 * value, not an error: the shares alone cannot tell how many are needed.
 */
export function combine(shares: Share[]): Uint8Array {
  if (shares.length === 0) throw new RangeError("no shares");
  const len = shares[0]!.y.length;
  const seen = new Set<number>();
  for (const s of shares) {
    if (!Number.isInteger(s.x) || s.x < 1 || s.x > 255) throw new RangeError("share x must be 1..255");
    if (seen.has(s.x)) throw new RangeError(`duplicate share x=${s.x}`);
    if (s.y.length !== len) throw new RangeError("shares have different lengths");
    seen.add(s.x);
  }
  const out = new Uint8Array(len);
  for (const si of shares) {
    let li = 1;
    for (const sj of shares) if (sj.x !== si.x) li = gfMul(li, gfDiv(sj.x, sj.x ^ si.x));
    for (let b = 0; b < len; b++) out[b]! ^= gfMul(si.y[b]!, li);
  }
  return out;
}
