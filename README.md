# eyalsec: the JavaScript and TypeScript client for the EyalSec API

[![npm](https://img.shields.io/npm/v/eyalsec.svg)](https://www.npmjs.com/package/eyalsec)
[![CI](https://github.com/EyalSec/eyalsec-js/actions/workflows/ci.yml/badge.svg)](https://github.com/EyalSec/eyalsec-js/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Work with your EyalSec account from Node.js: pull this week's critical events into a report, fail a pipeline on a new finding, label and annotate events in bulk, keep rules and filters in code, or add a machine from your provisioning script. Everything the [EyalSec API](https://eyalsec.com/docs/api) offers is a typed method here, with paging, retries and clear errors handled for you. It ships as both an ES module and CommonJS, with type definitions, and has no runtime dependencies.

```ts
import { EyalSec } from "eyalsec";

const client = new EyalSec(); // reads EYALSEC_API_KEY

for await (const event of client.iterEvents({ severity: ["critical", "high"], from: "2026-10-01" })) {
  console.log(event.created_at, event.severity, event.where, event.machine_name);
}
```

> **This package is the API client, not the runtime.** `npm install eyalsec` gives you this library. It is not es-python, the EyalSec Python runtime, and it adds no security checks to your program. The runtime is installed from your EyalSec dashboard: see the [Quick start](https://eyalsec.com/docs/quick-start).

## What EyalSec does

EyalSec follows untrusted data (requests, files, environment variables and more) through your running program and reports when it reaches a risky operation: a SQL query, a shell command, deserialization, a file path. Each event names the operation, the line of code, the value it received and where the untrusted part came from. You run your existing app through es-python, unchanged, and the events arrive on your dashboard. This library reads and manages them.

## Install

```bash
npm install eyalsec
```

Node.js 18 or newer. The client uses only the standard `fetch`, so other runtimes that provide it should work as well; Node.js is what the tests run on.

Keep your key on the server. Calling the API from a page in a visitor's browser would hand them your key.

## Get a key

Create an API key on your dashboard under **Settings > API access** and put it in `EYALSEC_API_KEY`. A **read-only key** can call every read, and it is the one to use for reports and dashboards; scripts that change things need a full key. See [API keys](https://eyalsec.com/docs/api-keys).

```bash
export EYALSEC_API_KEY=es2_your_key
node -e 'import("eyalsec").then(async ({ EyalSec }) => console.log(await new EyalSec().getAccount()))'
```

No account yet? [Book a live demo](https://eyalsec.com/contact) and we will set one up with you. Pricing is at [eyalsec.com/pricing](https://eyalsec.com/pricing).

## Examples

Field names are the API's own, exactly as the [API reference](https://eyalsec.com/docs/api) spells them, so a page of the reference reads straight across to the types here. Method names are camelCase.

### Events

```ts
const page = await client.queryEvents({ view: "python", sort: "severity" }); // one page, up to 100
for (const event of page.events) {
  console.log(event.id, event.severity, event.where, event.str_repr);
}

const detail = await client.getEvent(page.events[0].id); // the large fields
console.log(detail.trace, detail.source_code, detail.sink_code);

// What one run of a program produced.
for await (const run of client.iterRuns({ q: "manage.py", maxPages: 1 })) {
  for await (const event of client.iterEvents({ view: "python", run: run.run_uid })) {
    console.log(event.where, event.count);
  }
}

const csv = await client.exportEvents("csv", { view: "python", from: "2026-10-01" });
```

The API sends each event as an array, to keep large pages small. The client reads it by position into an object (`id`, `created_at`, `where`, `str_repr`, `severity`, ...) and keeps the original row in `raw`, plus any values a newer server adds in `extra`.

A short or empty page is not the last page: each request looks at a bounded slice of your history. `iterEvents` keeps following the cursor until it is empty, which is what you want almost every time.

### Triage

```ts
const label = await client.createLabel("needs review", "amber");
for await (const event of client.iterEvents({ tags: ["sqli"], bucket: "live" })) {
  await client.attachLabel(event.id, label.id);
  await client.setNote(event.id, "Queued for the Thursday review.");
}
```

### Rules and filters as code

```ts
import { RuleMode } from "eyalsec";

await client.createRule({ event_pattern: "^healthcheck", mode: RuleMode.HIDE, label: "health checks" });
await client.createFilter("^socket-recv$", "blacklist", { label: "noise" });
await client.setTaint("socket", "on"); // your account default
await client.applyRuleTemplate(3); // no machine means your global rules
```

### Machines and CI

```ts
const machine = await client.addMachine("web-02"); // build detected at install time
const command = await client.getInstallCommand(machine.PublicID, { attested: true });
console.log(command.script_path, command.expires_in); // the secret is single-use

const install = await client.ciInstall("ci-myrepo", { attested: true, distro: "ubuntu_24_04", arch: "x86_64" });
// ... run your tests under es-python ...
const result = await client.ciFindings("ci-myrepo", install.server_time, { min_severity: "high" });
if (result.findings > 0) {
  console.error(`${result.findings} findings at high or above: ${result.url}`);
  process.exitCode = 1;
}
```

`attested: true` is your confirmation that you are authorized to monitor that machine, the same box the dashboard asks you to tick.

A complete CI gate and a weekly report are in [`examples/`](examples).

## Errors

Every error the client throws is an `EyalSecError`. An error status becomes a subclass you can catch by meaning:

| Status | Error |
|---|---|
| 400 | `BadRequestError` |
| 401 | `AuthenticationError` (missing, wrong, revoked or expired key) |
| 403 | `PermissionDeniedError` (for example a read-only key trying to write) |
| 404 | `NotFoundError` (also for things on another account, so their existence is never confirmed) |
| 409 | `ConflictError` (for example the machine limit is reached) |
| 422 | `UnprocessableEntityError` |
| 429 | `RateLimitError`, with `retryAfter` in seconds |
| 5xx | `InternalServerError` |

Each carries `status`, `serverMessage`, `method` and `path`. A request that got no answer throws `APIConnectionError` (or `APITimeoutError`).

```ts
import { NotFoundError } from "eyalsec";

try {
  await client.getEvent(90210);
} catch (err) {
  if (err instanceof NotFoundError) console.log("no such event on this account");
  else throw err;
}
```

The client retries a rate-limited request after the server's `Retry-After` (up to `maxRetries`, default 2), and retries reads after a dropped connection or a 502, 503 or 504. Writes are never retried after a dropped connection, because there is no way to know whether they applied. The API's [rate limits](https://eyalsec.com/docs/api#rate-limits) are 300 requests a minute per account.

## Configuration

| Option | Environment | Default |
|---|---|---|
| `apiKey` | `EYALSEC_API_KEY` | none (required for everything but the two public lists) |
| `baseUrl` | `EYALSEC_URL` | `https://eyalsec.com` |
| `timeout` | | 30000 ms |
| `maxRetries` | | 2 |
| `fetch` | | the global `fetch`; pass your own for proxies, custom TLS or tests |
| `userAgent` | | added to the `User-Agent` header, such as `my-report/1.2` |

The key is sent only to `baseUrl`, only over HTTPS (plain `http://` is accepted for `localhost` alone), and never appears when the client is logged or serialized.

## Documentation

- The API this library calls: [eyalsec.com/docs/api](https://eyalsec.com/docs/api)
- EyalSec user guide: [eyalsec.com/docs](https://eyalsec.com/docs)

Related: [eyalsec-python](https://github.com/EyalSec/eyalsec-python) is the same client for Python, [eyalsec-cli](https://github.com/EyalSec/eyalsec-cli) is for the terminal, [eyalsec-mcp](https://github.com/EyalSec/eyalsec-mcp) is for AI assistants, and [es-python-action](https://github.com/EyalSec/es-python-action) is for GitHub Actions.

## Development

```bash
git clone https://github.com/EyalSec/eyalsec-js && cd eyalsec-js
npm ci
npm test
```

The tests run against a fake API. `npm run test:live` adds a read-only pass against your own account (set `EYALSEC_API_KEY`, and `EYALSEC_URL` if your account is not on eyalsec.com); `EYALSEC_LIVE_WRITES=1` also creates and removes a label, a filter, a rule, a saved search, a rule template and two machines. Point it at a test account, not one you depend on.

## Help

Questions and bug reports are welcome in [issues](https://github.com/EyalSec/eyalsec-js/issues), or write to support@eyalsec.com. Please send security reports to security@eyalsec.com rather than a public issue.

## License

MIT. See [LICENSE](LICENSE). The license covers this client library; your EyalSec account is governed by the [EyalSec terms](https://eyalsec.com/legal/terms).
