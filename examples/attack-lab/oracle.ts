/**
 * Stand-in for a polynomial-time NP solver. Each method solves an NP search
 * problem (find a witness that a fast check accepts) by exhaustive search on a
 * scaled-down instance. If P = NP, the same answers come back in polynomial
 * time at full size.
 */
import { createHash, createHmac } from "node:crypto";

export class PnpOracle {
  queries = 0;

  /** A nontrivial factor of n, by Pollard's rho. */
  factor(n: bigint): [bigint, bigint] {
    this.queries++;
    if (n % 2n === 0n) return [2n, n / 2n];
    const gcd = (a: bigint, b: bigint): bigint => {
      while (b) [a, b] = [b, a % b];
      return a;
    };
    for (let c = 1n; ; c++) {
      const f = (x: bigint) => (x * x + c) % n;
      let x = 2n;
      let y = 2n;
      let d = 1n;
      while (d === 1n) {
        x = f(x);
        y = f(f(y));
        d = gcd(x > y ? x - y : y - x, n);
      }
      if (d !== n) return [d, n / d];
    }
  }

  /** Any password whose salted SHA-256 equals the target. */
  invertPasswordHash(salt: string, target: string, dictionary: string[], alphabet: string, maxLen: number): string | null {
    this.queries++;
    const h = (p: string) => createHash("sha256").update(salt + p).digest("hex");
    for (const w of dictionary) if (h(w) === target) return w;
    const search = (prefix: string): string | null => {
      if (prefix && h(prefix) === target) return prefix;
      if (prefix.length === maxLen) return null;
      for (const ch of alphabet) {
        const r = search(prefix + ch);
        if (r) return r;
      }
      return null;
    };
    return search("");
  }

  /** An HMAC key consistent with every observed (body, mac) pair. Searches the unknown top bits. */
  recoverHmacKey(samples: { body: string; mac: string }[], unknownBits: number): Buffer | null {
    this.queries++;
    const key = Buffer.alloc(32);
    for (let k = 0; k < 2 ** unknownBits; k++) {
      const v = k << (24 - unknownBits);
      key[0] = (v >> 16) & 0xff;
      key[1] = (v >> 8) & 0xff;
      key[2] = v & 0xff;
      if (samples.every((s) => createHmac("sha256", key).update(s.body).digest("hex") === s.mac)) {
        return Buffer.from(key);
      }
    }
    return null;
  }
}
