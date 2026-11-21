# pnp-safe

Cryptographic primitives for TypeScript whose security does not depend on any
problem being hard to compute. If P = NP, AES, SHA-2, Argon2, RSA, elliptic
curves and lattice schemes all fall in principle. These do not.

> **License:** source-available, paid. Reading and a 30-day private evaluation
> are free; everything else needs a license. See [LICENSE](LICENSE) and reach
> out via [github.com/TheodoreAI](https://github.com/TheodoreAI) to agree on a price.

## What is inside

| Module | Main exports | Guarantee |
| --- | --- | --- |
| `entropy` | `JitterEntropySource`, `Extractor`, `randomBytes`, `estimateMinEntropy` | Toeplitz extractor output is within 2^-64 of uniform per block, given the source's min-entropy claim. |
| `otp` | `KeyPad`, `xor` | Perfect secrecy while no pad byte is reused. The pad enforces that. |
| `mac` | `polyMac`, `verifyPolyMac` | One-time forgery probability at most L / 2^127. |
| `aead` | `SecureChannel`, `encodeSealed`, `decodeSealed` | Encrypt-then-MAC from the two above; rejects replays. |
| `shamir` | `split`, `combine` | Fewer than k shares reveal nothing. |
| `password` | `PasswordHasher`, `InMemoryPepperStore` | A stolen database without the pepper reveals nothing about passwords while it holds fewer than t records. |

## Quick start

```ts
import { KeyPad, SecureChannel, randomBytes, split, combine,
         PasswordHasher, InMemoryPepperStore } from "pnp-safe";

// 1. Make a pad and hand an identical copy to the other side in person.
const material = randomBytes(1 << 20);
const alice = new SecureChannel(new KeyPad(material));
const bob = new SecureChannel(new KeyPad(material));
material.fill(0);

const sealed = alice.seal(new TextEncoder().encode("meet at noon"));
const plain = bob.open(sealed); // throws AuthenticationError if tampered

// 2. Split a secret 3-of-5.
const shares = split(new TextEncoder().encode("vault key"), 5, 3);
const secret = combine([shares[0], shares[2], shares[4]]);

// 3. Passwords. Keep the pepper out of the database.
const hasher = new PasswordHasher(InMemoryPepperStore.generate());
const record = await hasher.hash("hunter2");
await hasher.verify("hunter2", record); // true
```

## Rules you must follow

1. Never reuse pad bytes. Use one pad per direction and persist `KeyPad.serialize()` after every use.
2. A pad carries only as much traffic as its length. Each message costs its length plus 32 bytes.
3. `SystemEntropySource` is a seeded generator and is flagged `computational`. Make keys with the jitter source or hardware noise.
4. Check `estimateMinEntropy` on your hardware. Claim well below what it reports.
5. Rotate the pepper before the record count reaches `independence` (4096 by default), counting accounts an attacker can create.
6. Key distribution is out of scope: no public-key exchange survives P = NP.
7. JavaScript bigint arithmetic is not constant time. Timing side channels are out of scope.

## Development

```sh
npm install
npm test
```
