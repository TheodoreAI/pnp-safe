/**
 * Authenticated encryption from a one-time pad plus a one-time Wegman-Carter MAC
 * (encrypt-then-MAC). Each message consumes plaintext length + 32 pad bytes.
 */
import { concatBytes } from "./field.js";
import { MAC_KEY_BYTES, TAG_BYTES, polyMac, verifyPolyMac } from "./mac.js";
import { KeyPad, xor } from "./otp.js";

export class AuthenticationError extends Error {
  override name = "AuthenticationError";
}

export interface Sealed {
  /** Pad offset where this message's key bytes start. */
  offset: number;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

const HEADER_BYTES = 12;

function header(offset: number, length: number): Uint8Array {
  const h = new Uint8Array(HEADER_BYTES);
  const v = new DataView(h.buffer);
  v.setBigUint64(0, BigInt(offset));
  v.setUint32(8, length);
  return h;
}

export function encodeSealed(s: Sealed): Uint8Array {
  return concatBytes(header(s.offset, s.ciphertext.length), s.ciphertext, s.tag);
}

export function decodeSealed(data: Uint8Array): Sealed {
  if (data.length < HEADER_BYTES + TAG_BYTES) throw new RangeError("sealed message too short");
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const offset = Number(v.getBigUint64(0));
  const length = v.getUint32(8);
  if (data.length !== HEADER_BYTES + length + TAG_BYTES) throw new RangeError("sealed message length mismatch");
  return {
    offset,
    ciphertext: data.slice(HEADER_BYTES, HEADER_BYTES + length),
    tag: data.slice(HEADER_BYTES + length),
  };
}

/**
 * One direction of a pad-backed channel. The sender seals with its pad; the
 * receiver opens with an identical copy. Replays and reordering to an earlier
 * offset are rejected. A forged message never consumes receiver pad bytes.
 */
export class SecureChannel {
  constructor(private readonly pad: KeyPad) {}

  get remaining(): number {
    return this.pad.remaining;
  }

  /** Largest plaintext the pad can still carry in one message. */
  get capacity(): number {
    return Math.max(0, this.pad.remaining - MAC_KEY_BYTES);
  }

  seal(plaintext: Uint8Array): Sealed {
    const offset = this.pad.position;
    const key = this.pad.take(plaintext.length + MAC_KEY_BYTES);
    const ciphertext = xor(plaintext, key.subarray(0, plaintext.length));
    const tag = polyMac(key.subarray(plaintext.length), concatBytes(header(offset, ciphertext.length), ciphertext));
    key.fill(0);
    return { offset, ciphertext, tag };
  }

  open(sealed: Sealed): Uint8Array {
    const n = sealed.ciphertext.length;
    const key = this.pad.peek(sealed.offset, n + MAC_KEY_BYTES);
    const authed = concatBytes(header(sealed.offset, n), sealed.ciphertext);
    if (!verifyPolyMac(key.subarray(n), authed, sealed.tag)) {
      key.fill(0);
      throw new AuthenticationError("tag does not match");
    }
    this.pad.takeAt(sealed.offset, n + MAC_KEY_BYTES);
    const plaintext = xor(sealed.ciphertext, key.subarray(0, n));
    key.fill(0);
    return plaintext;
  }
}
