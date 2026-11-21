/**
 * One-time pad key management. The pad is the only secret: if a byte is never
 * used twice and the pad is uniformly random, ciphertexts reveal nothing but length.
 */
import { randomBytes, type EntropySource } from "./entropy.js";

export class KeyExhaustedError extends Error {
  override name = "KeyExhaustedError";
}

export class KeyReuseError extends Error {
  override name = "KeyReuseError";
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new RangeError("xor needs equal-length inputs");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/**
 * Pre-shared key bytes with a forward-only cursor. Bytes are wiped as they are
 * handed out, and the cursor never moves backward, so no byte is used twice.
 * Each direction of a conversation needs its own pad.
 */
export class KeyPad {
  private readonly bytes: Uint8Array;
  private cursor: number;

  /** Copies the material. Wipe your original copy after constructing. */
  constructor(material: Uint8Array, position = 0) {
    if (!Number.isSafeInteger(position) || position < 0 || position > material.length) {
      throw new RangeError("position out of range");
    }
    this.bytes = material.slice();
    this.bytes.fill(0, 0, position);
    this.cursor = position;
  }

  /** A fresh pad from the extractor. Copy it to the other party out of band. */
  static generate(length: number, source?: EntropySource): KeyPad {
    return new KeyPad(randomBytes(length, source));
  }

  get length(): number {
    return this.bytes.length;
  }

  /** Offset of the next unused byte. */
  get position(): number {
    return this.cursor;
  }

  get remaining(): number {
    return this.bytes.length - this.cursor;
  }

  private check(offset: number, n: number): void {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(n) || n < 0) throw new RangeError("bad offset or length");
    if (offset < this.cursor) throw new KeyReuseError(`offset ${offset} is before the cursor ${this.cursor}`);
    if (offset + n > this.bytes.length) throw new KeyExhaustedError(`need ${n} bytes at ${offset}, pad holds ${this.bytes.length}`);
  }

  /** Reads n bytes at offset without consuming them. Used to verify before committing. */
  peek(offset: number, n: number): Uint8Array {
    this.check(offset, n);
    return this.bytes.slice(offset, offset + n);
  }

  /** Consumes n bytes at offset, wiping them and any skipped bytes before it. */
  takeAt(offset: number, n: number): Uint8Array {
    this.check(offset, n);
    const out = this.bytes.slice(offset, offset + n);
    this.bytes.fill(0, this.cursor, offset + n);
    this.cursor = offset + n;
    return out;
  }

  /** Consumes the next n bytes. */
  take(n: number): Uint8Array {
    return this.takeAt(this.cursor, n);
  }

  /** 8-byte big-endian position followed by the pad (used bytes already zero). Persist after every use. */
  serialize(): Uint8Array {
    const out = new Uint8Array(8 + this.bytes.length);
    new DataView(out.buffer).setBigUint64(0, BigInt(this.cursor));
    out.set(this.bytes, 8);
    return out;
  }

  static deserialize(data: Uint8Array): KeyPad {
    if (data.length < 8) throw new RangeError("serialized pad too short");
    const position = Number(new DataView(data.buffer, data.byteOffset, 8).getBigUint64(0));
    return new KeyPad(data.subarray(8), position);
  }

  /** Zeroes the whole pad. */
  destroy(): void {
    this.bytes.fill(0);
    this.cursor = this.bytes.length;
  }
}
