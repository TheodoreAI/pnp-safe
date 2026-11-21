/**
 * Wegman-Carter one-time MAC over GF(2^127 - 1).
 *
 * tag = b + sum(m_i * a^(L-i)) mod p, with the key (a, b) used for ONE message.
 * For any two distinct messages, an attacker with unlimited computation forges
 * with probability at most L / 2^127, where L is the number of field elements.
 */
import { bytesToField, constantTimeEqual, encodeMessage, fieldToBytes, mod, polyHash } from "./field.js";

export const MAC_KEY_BYTES = 32;
export const TAG_BYTES = 16;

export function polyMac(key: Uint8Array, msg: Uint8Array): Uint8Array {
  if (key.length !== MAC_KEY_BYTES) throw new RangeError(`MAC key must be ${MAC_KEY_BYTES} bytes`);
  const a = bytesToField(key.subarray(0, 16));
  const b = bytesToField(key.subarray(16, 32));
  return fieldToBytes(mod(polyHash(a, encodeMessage(msg)) + b));
}

export function verifyPolyMac(key: Uint8Array, msg: Uint8Array, tag: Uint8Array): boolean {
  return constantTimeEqual(polyMac(key, msg), tag);
}
