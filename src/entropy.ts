/**
 * Randomness without hardness assumptions.
 *
 * A cryptographic PRNG stretches a short seed, and its security rests on one-way
 * functions. If P = NP, its seed can in principle be recovered from its output.
 * This module instead collects raw physical noise and runs it through a
 * Toeplitz-hashing extractor, whose output is provably close to uniform
 * (leftover hash lemma) given only a lower bound on the raw min-entropy.
 */
import { fromBase64 } from "./field.js";
import { DEFAULT_SEED_B64 } from "./seed.js";

export interface EntropySource {
  /** Returns n raw, possibly biased bytes. */
  read(n: number): Uint8Array;
  /** Conservative lower bound on min-entropy per raw byte, in bits (0 to 8]. */
  readonly minEntropyPerByte: number;
  /** True when the output comes from a seeded generator, not physical noise. */
  readonly computational: boolean;
}

export class EntropyHealthError extends Error {
  override name = "EntropyHealthError";
}

type Clock = () => bigint;


function pickClock(): { clock: Clock; perByte: number } {
  const proc = (globalThis as { process?: { hrtime?: { bigint?: () => bigint } } }).process;
  // Measured about 4.6 bits per sample on a Windows laptop (1M samples, longest
  // run 6). Claim far less, since other hardware may be quieter.
  if (proc?.hrtime?.bigint) return { clock: proc.hrtime.bigint, perByte: 1 };
  // Browsers coarsen performance.now(); claim very little entropy there.
  return { clock: () => BigInt(Math.floor(performance.now() * 1e6)), perByte: 0.05 };
}

const JITTER_MEM_WORDS = 1 << 20;
const JITTER_STEPS = 512;

/**
 * Raw bytes from CPU timing jitter: the low 8 bits of how long 512 data-dependent
 * reads and writes into a 4 MiB buffer take. Cache and memory-bus noise make the
 * timing vary, as in the jitterentropy library. The min-entropy claim is an estimate. Run your own assessment (for
 * example NIST SP 800-90B tools) on target hardware before relying on it.
 */
export class JitterEntropySource implements EntropySource {
  readonly computational = false;
  readonly minEntropyPerByte: number;
  private readonly clock: Clock;
  /** Repetition-count health test cutoff, as in NIST SP 800-90B 4.4.1. */
  private readonly maxRepeats: number;
  private readonly mem = new Uint32Array(JITTER_MEM_WORDS);
  private idx = 1;

  constructor(options: { minEntropyPerByte?: number } = {}) {
    const picked = pickClock();
    this.clock = picked.clock;
    this.minEntropyPerByte = options.minEntropyPerByte ?? picked.perByte;
    if (!(this.minEntropyPerByte > 0 && this.minEntropyPerByte <= 8)) {
      throw new RangeError("minEntropyPerByte must be in (0, 8]");
    }
    this.maxRepeats = 1 + Math.ceil(40 / this.minEntropyPerByte);
  }

  read(n: number): Uint8Array {
    const out = new Uint8Array(n);
    const mem = this.mem;
    let idx = this.idx;
    let last = -1;
    let repeats = 0;
    for (let i = 0; i < n; i++) {
      const t0 = this.clock();
      for (let k = 0; k < JITTER_STEPS; k++) {
        idx = (Math.imul(idx, 1103515245) + 12345 + mem[idx & (JITTER_MEM_WORDS - 1)]!) >>> 0;
        mem[idx & (JITTER_MEM_WORDS - 1)]! ^= k;
      }
      const dt = this.clock() - t0;
      const byte = Number(dt & 0xffn);
      out[i] = byte;
      repeats = byte === last ? repeats + 1 : 1;
      last = byte;
      if (repeats >= this.maxRepeats) throw new EntropyHealthError("jitter source is stuck on one value");
    }
    this.idx = idx;
    return out;
  }
}

/**
 * crypto.getRandomValues. Fast and fine in a world where P != NP, but it is a
 * seeded generator, so it is flagged computational.
 */
export class SystemEntropySource implements EntropySource {
  readonly computational = true;
  readonly minEntropyPerByte = 8;

  read(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, i + 65536));
    return out;
  }
}

function toWords(bytes: Uint8Array, extraWords = 1): Uint32Array {
  const w = new Uint32Array(Math.ceil(bytes.length / 4) + extraWords);
  for (let i = 0; i < bytes.length; i++) w[i >> 2] |= bytes[i]! << (8 * (i & 3));
  return w;
}

/**
 * Toeplitz extractor over GF(2): out = T * raw, where T[i][j] = seed[i - j + n - 1].
 * Bits are little-endian within each byte. Needs seed bits >= rawBits + outBits - 1.
 */
export function toeplitzExtract(raw: Uint8Array, seed: Uint8Array, outBits: number): Uint8Array {
  const n = raw.length * 8;
  if (!Number.isInteger(outBits) || outBits <= 0 || outBits % 8 !== 0) {
    throw new RangeError("outBits must be a positive multiple of 8");
  }
  if (seed.length * 8 < n + outBits - 1) throw new RangeError("seed too short for this raw/output size");
  const S = toWords(seed, 2);
  const mWords = Math.ceil(outBits / 32);
  const acc = new Uint32Array(mWords);
  for (let j = 0; j < n; j++) {
    if (((raw[j >> 3]! >> (j & 7)) & 1) === 0) continue;
    // Column j of T is the seed window starting at bit n - 1 - j.
    const s = n - 1 - j;
    const q = s >> 5;
    const r = s & 31;
    if (r === 0) {
      for (let k = 0; k < mWords; k++) acc[k]! ^= S[q + k]!;
    } else {
      for (let k = 0; k < mWords; k++) acc[k]! ^= (S[q + k]! >>> r) | (S[q + k + 1]! << (32 - r));
    }
  }
  const out = new Uint8Array(outBits / 8);
  for (let i = 0; i < out.length; i++) out[i] = (acc[i >> 2]! >>> (8 * (i & 3))) & 0xff;
  return out;
}

/** Statistical distance from uniform is at most 2^-SECURITY_BITS per block. */
export const EXTRACTOR_SECURITY_BITS = 64;
const RAW_BLOCK_BYTES = 2048;

/**
 * Pulls raw blocks from a source and emits as many uniform bytes per block as
 * the leftover hash lemma allows: floor(k - 2 * SECURITY_BITS) bits, where k is
 * the block's claimed min-entropy.
 */
export class Extractor {
  readonly outBitsPerBlock: number;
  private readonly seed: Uint8Array;
  private buffer: Uint8Array = new Uint8Array(0);

  constructor(readonly source: EntropySource, seed: Uint8Array = fromBase64(DEFAULT_SEED_B64)) {
    const k = Math.floor(RAW_BLOCK_BYTES * source.minEntropyPerByte);
    this.outBitsPerBlock = Math.floor((k - 2 * EXTRACTOR_SECURITY_BITS) / 8) * 8;
    if (this.outBitsPerBlock <= 0) throw new RangeError("source min-entropy too low for one block");
    if (seed.length * 8 < RAW_BLOCK_BYTES * 8 + this.outBitsPerBlock - 1) throw new RangeError("seed too short");
    this.seed = seed;
  }

  read(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let filled = 0;
    while (filled < n) {
      if (this.buffer.length === 0) {
        this.buffer = toeplitzExtract(this.source.read(RAW_BLOCK_BYTES), this.seed, this.outBitsPerBlock);
      }
      const take = Math.min(n - filled, this.buffer.length);
      out.set(this.buffer.subarray(0, take), filled);
      this.buffer.fill(0, 0, take);
      this.buffer = this.buffer.subarray(take);
      filled += take;
    }
    return out;
  }
}

let defaultExtractor: Extractor | undefined;
const extractors = new WeakMap<EntropySource, Extractor>();

/** n uniform bytes. Default: timing jitter through the Toeplitz extractor. */
export function randomBytes(n: number, source?: EntropySource): Uint8Array {
  if (!Number.isInteger(n) || n < 0) throw new RangeError("n must be a non-negative integer");
  if (!source) {
    defaultExtractor ??= new Extractor(new JitterEntropySource());
    return defaultExtractor.read(n);
  }
  let ex = extractors.get(source);
  if (!ex) {
    ex = new Extractor(source);
    extractors.set(source, ex);
  }
  return ex.read(n);
}

/**
 * Most-common-value estimate of min-entropy per byte (NIST SP 800-90B 6.3.1,
 * without the confidence bound). Use it to sanity-check a source's claim on
 * your hardware; it is an upper estimate, so claim noticeably less.
 */
export function estimateMinEntropy(source: EntropySource, samples = 100_000): number {
  const counts = new Uint32Array(256);
  for (const b of source.read(samples)) counts[b]!++;
  return -Math.log2(Math.max(...counts) / samples);
}
