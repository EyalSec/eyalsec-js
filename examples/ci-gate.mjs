// Fail a CI job when a test run under es-python reached a finding at or above
// a severity. Run it after your tests, on the same machine name the install
// step used:
//
//   EYALSEC_API_KEY=es2_... node examples/ci-gate.mjs ci-myrepo 2026-10-07T12:00:00Z high
//
// The second argument is when the run started. Prefer the server's clock: the
// `server_time` that `ciInstall` returned, or a `Date` response header.
// A read-only key is enough.

import { EyalSec } from "eyalsec";

const [machine, since, minSeverity = "high"] = process.argv.slice(2);
if (!machine || !since) {
  console.error("usage: node ci-gate.mjs <machine-name> <since> [critical|high|medium|low|info]");
  process.exit(2);
}

const client = new EyalSec();
const result = await client.ciFindings(machine, since, { min_severity: minSeverity, limit: 20 });

console.log(`${result.total} events on ${machine} since ${result.since}; ${result.findings} at ${minSeverity} or above (${result.new_findings} new).`);
for (const f of result.events) {
  console.log(`  ${f.severity.padEnd(8)} ${f.where}  (event ${f.id}${f.new ? ", new" : ""})`);
}
if (result.hidden_by) console.log(`Note: your Hide rule "${result.hidden_by}" hides every es-python event, so nothing could be counted.`);
if (result.findings > 0) {
  console.log(`Open them on the dashboard: ${result.url}`);
  process.exitCode = 1;
}
