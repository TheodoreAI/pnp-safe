/**
 * Password verification that survives P = NP, as long as the pepper stays out
 * of the database.
 *
 * tag = g(h_a(salt || password)), where h_a is the polynomial universal hash and
 * g is a random polynomial of degree t - 1. Both a and g's coefficients form the
 * pepper. Values of g at t or fewer distinct points are independent and uniform,
 * so a thief holding fewer than t records (counting accounts they created
 * themselves) sees tags that carry no information about any password. No amount
 * of computation can then test a guess offline.
 */
import { randomBytes, type EntropySource } from "./entropy.js";
import {
  bytesToField,
  concatBytes,
  constantTimeEqual,
  encodeMessage,
  fieldToBytes,
  fromBase64,
  mod,
  polyHash,
  toBase64,
} from "./field.js";

/** The record count the information-theoretic guarantee covers by default. */
export const DEFAULT_INDEPENDENCE = 4096;
export const SALT_BYTES = 16;

/** Holds the pepper and computes tags, ideally inside an HSM or a separate service. */
export interface PepperStore {
  /** Records the guarantee covers before the pepper must be rotated. */
  readonly independence: number;
  tag(input: Uint8Array): Promise<Uint8Array>;
}

export class InMemoryPepperStore implements PepperStore {
  readonly independence: number;
  private readonly a: bigint;
  private readonly coeffs: bigint[];

  static keyBytes(independence: number): number {
    return 16 * (independence + 1);
  }

  /** Builds a pepper from the extractor. Slow by design with the default jitter source. */
  static generate(independence = DEFAULT_INDEPENDENCE, source?: EntropySource): InMemoryPepperStore {
    for (;;) {
      const key = randomBytes(InMemoryPepperStore.keyBytes(independence), source);
      if (bytesToField(key.subarray(0, 16)) !== 0n) return new InMemoryPepperStore(key);
    }
  }

  constructor(key: Uint8Array) {
    if (key.length < 32 || key.length % 16 !== 0) throw new RangeError("pepper must be 16 * (t + 1) bytes, t >= 1");
    this.independence = key.length / 16 - 1;
    this.a = bytesToField(key.subarray(0, 16));
    if (this.a === 0n) throw new RangeError("pepper hash key is zero; generate a new pepper");
    this.coeffs = [];
    for (let i = 16; i < key.length; i += 16) this.coeffs.push(bytesToField(key.subarray(i, i + 16)));
  }

  async tag(input: Uint8Array): Promise<Uint8Array> {
    const x = polyHash(this.a, encodeMessage(input));
    let y = 0n;
    for (const c of this.coeffs) y = mod(y * x + c);
    return fieldToBytes(y);
  }
}

export interface PasswordRecord {
  salt: string;
  tag: string;
}

export class PasswordHasher {
  constructor(
    private readonly store: PepperStore,
    private readonly source?: EntropySource,
  ) {}

  private input(salt: Uint8Array, password: string): Uint8Array {
    return concatBytes(salt, new TextEncoder().encode(password.normalize("NFC")));
  }

  async hash(password: string): Promise<PasswordRecord> {
    const salt = randomBytes(SALT_BYTES, this.source);
    const tag = await this.store.tag(this.input(salt, password));
    return { salt: toBase64(salt), tag: toBase64(tag) };
  }

  async verify(password: string, record: PasswordRecord): Promise<boolean> {
    const tag = await this.store.tag(this.input(fromBase64(record.salt), password));
    return constantTimeEqual(tag, fromBase64(record.tag));
  }
}
