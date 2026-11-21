/** Legitimate users generating real traffic for the attacker to target. */
import { randomBytes as nodeRandom } from "node:crypto";
import { SecureChannel, encodeSealed, toBase64, type KeyPad } from "../../src/index.js";
import { aesGcmEncrypt, rsaEncryptBytes } from "./legacy.js";

export const USERS = { alice: "sunshine", bob: "kq7" } as const;
export const MESSAGE_1 = "Wire $25,000 to account 4471 on Friday";
export const MESSAGE_2 = "Wire $25,000 to account 4471 on Monday";

export async function api(base: string, method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(base + path, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: await res.json() };
}

/** Registers users, sends one message per vault, and leaves a second pnp message in flight. */
export async function seedTraffic(base: string, pad: KeyPad): Promise<{ deliverInFlight: () => Promise<number> }> {
  for (const [user, password] of Object.entries(USERS)) {
    await api(base, "POST", "/legacy/register", { user, password });
    await api(base, "POST", "/pnp/register", { user, password });
  }

  // Legacy: hybrid RSA + AES-256-GCM.
  const pub = (await api(base, "GET", "/legacy/pubkey")).json;
  const aesKey = nodeRandom(32);
  await api(base, "POST", "/legacy/send", {
    from: "alice",
    encKey: rsaEncryptBytes({ n: BigInt(pub.n), e: BigInt(pub.e) }, aesKey),
    box: aesGcmEncrypt(aesKey, MESSAGE_1),
  });

  // pnp-safe: pad channel.
  const channel = new SecureChannel(pad);
  const enc = (m: string) => toBase64(encodeSealed(channel.seal(new TextEncoder().encode(m))));
  await api(base, "POST", "/pnp/send", { from: "alice", sealed: enc(MESSAGE_1) });
  const second = enc(MESSAGE_2);
  await api(base, "POST", "/net/inflight", { from: "alice", sealed: second });
  return { deliverInFlight: async () => (await api(base, "POST", "/pnp/send", { from: "alice", sealed: second })).status };
}
