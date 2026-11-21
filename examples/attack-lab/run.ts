/**
 * npm run lab            run the attack suite once and print the report
 * npm run lab -- --serve also serve the dashboard at http://127.0.0.1:8787
 *
 * Exits with code 1 if any expectation fails: a legacy primitive that held, or
 * a pnp-safe primitive that broke inside its threat model.
 */
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { runAttacks, type Finding } from "./attack.js";
import { api, MESSAGE_2, seedTraffic } from "./client.js";
import { PnpOracle } from "./oracle.js";
import { RSA_BITS, HMAC_UNKNOWN_BITS } from "./legacy.js";
import { PAD_BYTES, PNP_INDEPENDENCE, startLab, type Lab } from "./server.js";

const here = dirname(fileURLToPath(import.meta.url));
// Compiled to dist/examples/attack-lab; the page lives in the source tree.
const publicDir = resolve(here, "../../../examples/attack-lab/public");

export interface Report {
  ranAt: string;
  setup: Record<string, string>;
  findings: Finding[];
  expectationsMet: boolean;
  totalMs: number;
}

async function runOnce(lab: Lab): Promise<Report> {
  const t0 = performance.now();
  lab.reset();
  const { deliverInFlight } = await seedTraffic(lab.url, lab.clientPad());
  const findings = await runAttacks(lab.url, new PnpOracle());

  // The real in-flight message arrives after all the forgeries. If the pad had
  // been burned or desynchronised, this would fail.
  const t = performance.now();
  const status = await deliverInFlight();
  const truth = (await api(lab.url, "GET", "/lab/truth")).json;
  const arrived = status === 202 && truth.pnpInbox.at(-1) === MESSAGE_2;
  findings.push({
    side: "pnp-safe",
    target: "Pad exhaustion (denial of service)",
    attack: "Afterwards: does the genuine in-flight message still decrypt?",
    outcome: arrived ? "HELD" : "BROKEN",
    evidence: `genuine message answered HTTP ${status}; server inbox now ends with "${truth.pnpInbox.at(-1)}"`,
    ms: Math.round(performance.now() - t),
  });

  const expectationsMet = findings.every((f) => (f.side === "legacy" ? f.outcome === "BROKEN" : f.outcome !== "BROKEN"));
  return {
    ranAt: new Date().toISOString(),
    setup: {
      "Legacy RSA modulus": `${RSA_BITS} bits (scaled down so the stand-in oracle finishes)`,
      "Legacy HMAC key": `256 bits, ${HMAC_UNKNOWN_BITS} unknown (scaled down)`,
      "Legacy passwords": "salted SHA-256, full strength",
      "pnp-safe pad": `${PAD_BYTES} bytes, full-size 127-bit MAC`,
      "pnp-safe pepper": `t = ${PNP_INDEPENDENCE}-wise independent`,
      "pnp-safe Shamir": "3-of-5 over GF(256), 2 shares stolen",
    },
    findings,
    expectationsMet,
    totalMs: Math.round(performance.now() - t0),
  };
}

function print(r: Report): void {
  const color = (o: string) => (o === "HELD" ? "\x1b[32m" : o === "BROKEN" ? "\x1b[31m" : "\x1b[33m") + o.padEnd(21) + "\x1b[0m";
  for (const side of ["legacy", "pnp-safe"] as const) {
    console.log(`\n== ${side.toUpperCase()} ==`);
    for (const f of r.findings.filter((x) => x.side === side)) {
      console.log(`${color(f.outcome)} ${f.target} - ${f.attack} (${f.ms} ms)`);
      console.log(`${" ".repeat(22)}${f.evidence}`);
    }
  }
  console.log(`\nExpectations ${r.expectationsMet ? "\x1b[32mMET" : "\x1b[31mNOT MET"}\x1b[0m in ${r.totalMs} ms`);
}

const serve = process.argv.includes("--serve");
const lab = await startLab(serve ? 8787 : 0, publicDir);
lab.onAttack = async () => (lab.lastReport = await runOnce(lab));
const report = await runOnce(lab);
lab.lastReport = report;
print(report);
if (serve) {
  console.log(`\nDashboard: ${lab.url}  (Ctrl+C to stop)`);
} else {
  await lab.close();
  process.exitCode = report.expectationsMet ? 0 : 1;
}
