// Print the last seven days of critical and high events as a Markdown table,
// most severe first: paste it into a ticket or a weekly review.
//
//   EYALSEC_API_KEY=es2_... node examples/weekly-report.mjs > report.md
//
// A read-only key is enough.

import { EyalSec } from "eyalsec";

const client = new EyalSec();
const since = new Date(Date.now() - 7 * 24 * 3600 * 1000);

const rows = [];
for await (const e of client.iterEvents({ severity: ["critical", "high"], from: since, sort: "severity" })) {
  rows.push(e);
  if (rows.length >= 500) break;
}

const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\s+/g, " ").slice(0, 80);
console.log(`# EyalSec events since ${since.toISOString().slice(0, 10)}\n`);
if (rows.length === 0) {
  console.log("No critical or high events this week.");
} else {
  console.log("| Severity | Operation | Machine | Count | First seen | Event |");
  console.log("|---|---|---|---|---|---|");
  for (const e of rows) {
    console.log(`| ${e.severity} | ${cell(e.where)} | ${cell(e.machine_name)} | ${e.count} | ${e.created_at.slice(0, 10)} | ${e.id} |`);
  }
}
