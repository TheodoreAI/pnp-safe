# pnp-safe

Cryptographic primitives for TypeScript whose security does not depend on any
problem being hard to compute. If P = NP, AES, SHA-2, Argon2, RSA, elliptic
curves and lattice schemes all fall in principle. These do not.

> **License:** source-available, paid. Reading and a 30-day private evaluation
> are free; everything else needs a license. See [LICENSE](LICENSE) and reach
> out at [mateoej12@gmail.com](mailto:mateoej12@gmail.com) or via
> [github.com/TheodoreAI](https://github.com/TheodoreAI) to agree on a price.

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

## Attack lab

`examples/attack-lab` runs an HTTP server with two vaults side by side. One uses
RSA, AES-256-GCM, salted SHA-256 and HMAC tokens. The other uses pnp-safe. An
attacker with a network tap, a stolen database and a stand-in P = NP oracle
then attacks both.

```sh
npm run lab               # run once, print the report, exit 1 if any expectation fails
npm run lab -- --serve    # same, then serve a dashboard at http://127.0.0.1:8787
```

No real P = NP solver exists, so the oracle uses exhaustive search on
scaled-down classical keys: a 64-bit RSA modulus and an HMAC key with 20
unknown bits. pnp-safe runs at full size. Its attacks go further than search:
the attacker constructs every key that fits what it observed, and shows that
contradictory answers fit equally well.

| Vault | Attack | Result |
| --- | --- | --- |
| Legacy | Factor RSA, unwrap the AES key, read the message | Broken |
| Legacy | Forge an RSA signature | Broken |
| Legacy | Invert stolen SHA-256 password hashes, log in | Broken |
| Legacy | Recover the HMAC key, mint an admin token | Broken |
| pnp-safe | Search every pad key for the plaintext | Held: only the length leaks |
| pnp-safe | Bit-flip an in-flight message and re-tag it (204 forgeries) | Held: 0 accepted |
| pnp-safe | Replay a delivered message | Held |
| pnp-safe | Forge far ahead to burn the receiver's pad | Held: the real message still arrives |
| pnp-safe | Test password guesses against a stolen table | Held: any guesses fit some pepper |
| pnp-safe | Solve a 3-of-5 Shamir secret from 2 shares | Held: every secret fits |
| pnp-safe | Steal the pepper too (out of model) | Broken, as documented |

Injected bugs are caught. Disabling MAC verification, disabling both the pad
cursor check and byte wiping, or holding more records than the pepper's
independence bound each turn a finding from held to broken.

## Development

```sh
npm install
npm test
```
