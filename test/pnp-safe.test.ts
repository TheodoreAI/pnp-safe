import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AuthenticationError,
  Extractor,
  InMemoryPepperStore,
  JitterEntropySource,
  estimateMinEntropy,
  KeyExhaustedError,
  KeyPad,
  KeyReuseError,
  P127,
  PasswordHasher,
  SecureChannel,
  SystemEntropySource,
  combine,
  decodeSealed,
  encodeMessage,
  encodeSealed,
  fieldToBytes,
  bytesToField,
  gfDiv,
  gfMul,
  polyMac,
  randomBytes,
  split,
  toeplitzExtract,
  verifyPolyMac,
} from "../src/index.js";

const sys = new SystemEntropySource();
const bytes = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe("field", () => {
  it("round-trips field elements", () => {
    for (const x of [0n, 1n, 12345678901234567890n, P127 - 1n]) assert.equal(bytesToField(fieldToBytes(x)), x);
  });
  it("encodes distinct messages distinctly, including zero padding cases", () => {
    const seen = new Set<string>();
    for (const m of [new Uint8Array(0), new Uint8Array(1), new Uint8Array(2), new Uint8Array(15), new Uint8Array(16), Uint8Array.of(1), Uint8Array.of(0, 1)]) {
      const key = encodeMessage(m).join(",");
      assert.ok(!seen.has(key), `collision for length ${m.length}`);
      seen.add(key);
    }
  });
});

describe("mac", () => {
  it("verifies and rejects tampering", () => {
    const key = randomBytes(32, sys);
    const msg = bytes("transfer 10 coins to alice");
    const tag = polyMac(key, msg);
    assert.ok(verifyPolyMac(key, msg, tag));
    assert.ok(!verifyPolyMac(key, bytes("transfer 99 coins to alice"), tag));
    assert.ok(!verifyPolyMac(key, Uint8Array.of(...msg, 0), tag));
    const bad = tag.slice();
    bad[0]! ^= 1;
    assert.ok(!verifyPolyMac(key, msg, bad));
  });
});

describe("entropy", () => {
  it("matches a naive Toeplitz matrix product", () => {
    const raw = randomBytes(9, sys);
    const outBits = 40;
    const n = raw.length * 8;
    const seed = randomBytes(Math.ceil((n + outBits - 1) / 8), sys);
    const bit = (b: Uint8Array, i: number) => (b[i >> 3]! >> (i & 7)) & 1;
    const expected = new Uint8Array(outBits / 8);
    for (let i = 0; i < outBits; i++) {
      let v = 0;
      for (let j = 0; j < n; j++) v ^= bit(seed, i - j + n - 1) & bit(raw, j);
      expected[i >> 3]! |= v << (i & 7);
    }
    assert.deepEqual(toeplitzExtract(raw, seed, outBits), expected);
  });
  it("produces balanced output from the jitter source", () => {
    const ex = new Extractor(new JitterEntropySource());
    const out = ex.read(4096);
    let ones = 0;
    for (const b of out) for (let i = 0; i < 8; i++) ones += (b >> i) & 1;
    const ratio = ones / (out.length * 8);
    assert.ok(ratio > 0.48 && ratio < 0.52, `ones ratio ${ratio}`);
  });
  it("claims less min-entropy than it measures", () => {
    const src = new JitterEntropySource();
    assert.ok(estimateMinEntropy(src, 20_000) > src.minEntropyPerByte);
  });
  it("flags the system source as computational", () => {
    assert.equal(sys.computational, true);
    assert.equal(new JitterEntropySource().computational, false);
  });
});

describe("otp", () => {
  it("never hands out a byte twice", () => {
    const pad = new KeyPad(randomBytes(64, sys));
    pad.take(10);
    assert.throws(() => pad.takeAt(5, 2), KeyReuseError);
    assert.throws(() => pad.take(100), KeyExhaustedError);
    pad.takeAt(20, 4);
    assert.equal(pad.position, 24);
  });
  it("survives serialize and deserialize with the cursor intact", () => {
    const pad = new KeyPad(randomBytes(32, sys));
    pad.take(8);
    const copy = KeyPad.deserialize(pad.serialize());
    assert.equal(copy.position, 8);
    assert.deepEqual(copy.take(4), pad.take(4));
  });
});

describe("aead", () => {
  const pair = () => {
    const material = randomBytes(1024, sys);
    return [new SecureChannel(new KeyPad(material)), new SecureChannel(new KeyPad(material))] as const;
  };
  it("round-trips through the wire format", () => {
    const [alice, bob] = pair();
    for (const m of ["hello", "", "a longer message that spans several field chunks"]) {
      assert.equal(text(bob.open(decodeSealed(encodeSealed(alice.seal(bytes(m)))))), m);
    }
  });
  it("rejects a flipped ciphertext bit", () => {
    const [alice, bob] = pair();
    const s = alice.seal(bytes("attack at dawn"));
    s.ciphertext[0]! ^= 1;
    assert.throws(() => bob.open(s), AuthenticationError);
  });
  it("rejects replays", () => {
    const [alice, bob] = pair();
    const s = alice.seal(bytes("once"));
    bob.open(s);
    assert.throws(() => bob.open(s), KeyReuseError);
  });
  it("does not let a forgery at a far offset burn the receiver's pad", () => {
    const [alice, bob] = pair();
    assert.throws(() => bob.open({ offset: 900, ciphertext: new Uint8Array(4), tag: new Uint8Array(16) }), AuthenticationError);
    assert.equal(text(bob.open(alice.seal(bytes("still fine")))), "still fine");
  });
});

describe("shamir", () => {
  it("does GF(256) arithmetic consistently", () => {
    for (let a = 1; a < 256; a += 7) for (let b = 1; b < 256; b += 11) assert.equal(gfDiv(gfMul(a, b), b), a);
    assert.equal(gfMul(0x57, 0x83), 0xc1);
  });
  it("rebuilds from every 3-of-5 subset", () => {
    const secret = bytes("correct horse battery staple");
    const shares = split(secret, 5, 3, sys);
    for (let i = 0; i < 5; i++)
      for (let j = i + 1; j < 5; j++)
        for (let k = j + 1; k < 5; k++) assert.deepEqual(combine([shares[i]!, shares[j]!, shares[k]!]), secret);
    assert.notDeepEqual(combine(shares.slice(0, 2)), secret);
  });
});

describe("password", () => {
  const store = InMemoryPepperStore.generate(64, sys);
  const hasher = new PasswordHasher(store, sys);
  it("verifies the right password only", async () => {
    const rec = await hasher.hash("hunter2");
    assert.ok(await hasher.verify("hunter2", rec));
    assert.ok(!(await hasher.verify("hunter3", rec)));
  });
  it("salts equal passwords differently", async () => {
    const [a, b] = await Promise.all([hasher.hash("same"), hasher.hash("same")]);
    assert.notEqual(a.tag, b.tag);
  });
  it("reports its independence bound and rejects malformed peppers", () => {
    assert.equal(store.independence, 64);
    assert.throws(() => new InMemoryPepperStore(new Uint8Array(20)), RangeError);
  });
});
