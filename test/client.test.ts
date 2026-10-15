import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { inspect } from "node:util";

import {
  APIConnectionError,
  APITimeoutError,
  AuthenticationError,
  ConfigurationError,
  ConflictError,
  EyalSec,
  NotFoundError,
  PermissionDeniedError,
  RateLimitError,
  RuleMode,
  UnexpectedResponseError,
  VERSION,
  eventFromRow,
  type FetchLike,
} from "eyalsec";

const KEY = "es2_TESTKEYdoNotUse000000000000000000000000000";

interface Call {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

type Reply = { status?: number; body?: unknown; headers?: Record<string, string> } | Error;

/** A fake fetch that answers from a script and records every request. */
function fakeFetch(...replies: Reply[]): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url: new URL(url), method: init.method, headers: init.headers, body: init.body });
    const r = replies.shift();
    if (r === undefined) throw new Error(`unexpected request ${init.method} ${url}`);
    if (r instanceof Error) throw r;
    const headers = new Map(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    let text = "";
    if (typeof r.body === "string") text = r.body;
    else if (r.body !== undefined) {
      text = JSON.stringify(r.body);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
    return {
      status: r.status ?? 200,
      headers: { get: (n: string) => headers.get(n.toLowerCase()) ?? null },
      text: async () => text,
    };
  };
  return { fetch, calls };
}

function client(fetch: FetchLike, extra: Partial<ConstructorParameters<typeof EyalSec>[0]> = {}) {
  return new EyalSec({ apiKey: KEY, baseUrl: "https://example.test", fetch, maxRetries: 2, ...extra });
}

const ROW = [
  "2026-07-05T12:00:00Z",
  "socket-recv",
  "'...'",
  3,
  "web-01",
  "high",
  "python",
  12345,
  "",
  "",
  false,
  "This value was not sanitized.",
  [{ label: "data exfiltration", sev: "medium" }],
  [{ id: 1, name: "triage", color: "amber" }],
  false,
  "",
  "socket",
  "a-future-field",
];

describe("configuration", () => {
  it("sends the key, an Accept and a User-Agent header to the base URL", async () => {
    const f = fakeFetch({ body: { username: "alice" } });
    const a = await client(f.fetch).getAccount();
    assert.equal(a.username, "alice");
    const c = f.calls[0]!;
    assert.equal(c.url.origin, "https://example.test");
    assert.equal(c.url.pathname, "/api/account/");
    assert.equal(c.method, "GET");
    assert.equal(c.headers["X-API-Key"], KEY);
    assert.equal(c.headers.Accept, "application/json");
    assert.match(c.headers["User-Agent"]!, new RegExp(`^eyalsec-js/${VERSION.replace(/\./g, "\\.")}`));
  });

  it("refuses to call a keyed endpoint without a key, and sends nothing", async () => {
    const f = fakeFetch();
    const prev = process.env.EYALSEC_API_KEY;
    delete process.env.EYALSEC_API_KEY;
    try {
      const c = new EyalSec({ baseUrl: "https://example.test", fetch: f.fetch });
      assert.equal(c.hasApiKey, false);
      await assert.rejects(c.listMachines(), ConfigurationError);
      assert.equal(f.calls.length, 0);
    } finally {
      if (prev !== undefined) process.env.EYALSEC_API_KEY = prev;
    }
  });

  it("calls the two public lists without a key", async () => {
    const f = fakeFetch(
      { body: { distros: [{ id: "ubuntu_24_04", label: "Ubuntu 24.04 LTS", archs: ["x86_64"] }] } },
      { body: { versions: ["3.12", "3.13"], default: "3.13" } },
    );
    const c = new EyalSec({ apiKey: "", baseUrl: "https://example.test", fetch: f.fetch });
    assert.equal((await c.listSupportedOsTypes())[0]!.id, "ubuntu_24_04");
    assert.equal((await c.listSupportedPythonVersions("ubuntu_24_04_x86_64")).default, "3.13");
    assert.equal(f.calls[0]!.headers["X-API-Key"], undefined);
    assert.equal(f.calls[1]!.url.searchParams.get("os"), "ubuntu_24_04_x86_64");
  });

  it("reads EYALSEC_API_KEY and EYALSEC_URL", async () => {
    const f = fakeFetch({ body: {} });
    process.env.EYALSEC_API_KEY = KEY;
    process.env.EYALSEC_URL = "https://other.test/";
    try {
      const c = new EyalSec({ fetch: f.fetch });
      assert.equal(c.baseUrl, "https://other.test");
      await c.getAccount();
      assert.equal(f.calls[0]!.headers["X-API-Key"], KEY);
    } finally {
      delete process.env.EYALSEC_API_KEY;
      delete process.env.EYALSEC_URL;
    }
  });

  it("defaults to https://eyalsec.com", () => {
    const prev = process.env.EYALSEC_URL;
    delete process.env.EYALSEC_URL;
    try {
      assert.equal(new EyalSec({ apiKey: KEY, fetch: fakeFetch().fetch }).baseUrl, "https://eyalsec.com");
    } finally {
      if (prev !== undefined) process.env.EYALSEC_URL = prev;
    }
  });

  it("refuses plain http except to this machine", () => {
    const { fetch } = fakeFetch();
    assert.throws(() => new EyalSec({ apiKey: KEY, baseUrl: "http://eyalsec.com", fetch }), ConfigurationError);
    assert.throws(() => new EyalSec({ apiKey: KEY, baseUrl: "ftp://x", fetch }), ConfigurationError);
    assert.throws(() => new EyalSec({ apiKey: KEY, baseUrl: "not a url", fetch }), ConfigurationError);
    assert.equal(new EyalSec({ apiKey: KEY, baseUrl: "http://localhost:1027/", fetch }).baseUrl, "http://localhost:1027");
  });

  it("never shows the key when the client is logged or serialized", () => {
    const c = client(fakeFetch().fetch);
    assert.ok(!inspect(c, { showHidden: true, depth: 5 }).includes(KEY));
    assert.ok(!JSON.stringify(c).includes(KEY));
  });

  it("keeps its version in step with package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string };
    assert.equal(VERSION, pkg.version);
  });
});

describe("events", () => {
  it("builds the query body from the filters and reads rows by position", async () => {
    const f = fakeFetch({
      body: {
        events: [ROW],
        next_cursor: "abc",
        scanned: 1,
        exhausted: false,
        oldest_examined: "2026-07-05T12:00:00Z",
        event_limit: 25000,
        event_limit_monthly: true,
      },
    });
    const page = await client(f.fetch).queryEvents({
      view: "python",
      severity: "critical, high" as never,
      from: new Date("2026-06-01T00:00:00Z"),
      to: "2026-06-30",
      tags: ["sqli"],
      labels: [1],
      run: "9f2c1d4ab8e0472c93ad5f6178be20c4",
      cursor: "prev",
      extra: { future: true },
    });
    const c = f.calls[0]!;
    assert.equal(c.method, "POST");
    assert.equal(c.url.pathname, "/api/get_all_events_with_count/");
    assert.equal(c.headers["Content-Type"], "application/json");
    assert.deepEqual(JSON.parse(c.body!), {
      view: "python",
      severity: ["critical", "high"],
      from: "2026-06-01T00:00:00.000Z",
      to: "2026-06-30",
      tags: ["sqli"],
      labels: [1],
      advanced: { match: "all", conditions: [{ field: "run", op: "is", value: "9f2c1d4ab8e0472c93ad5f6178be20c4" }] },
      cursor: "prev",
      future: true,
    });
    assert.equal(page.next_cursor, "abc");
    assert.equal(page.event_limit, 25000);
    const e = page.events[0]!;
    assert.equal(e.id, 12345);
    assert.equal(e.where, "socket-recv");
    assert.equal(e.severity, "high");
    assert.equal(e.count, 3);
    assert.equal(e.taint_source, "socket");
    assert.deepEqual(e.impact, [{ label: "data exfiltration", sev: "medium" }]);
    assert.deepEqual(e.labels, [{ id: 1, name: "triage", color: "amber" }]);
    assert.deepEqual(e.extra, ["a-future-field"]);
    assert.equal(e.raw.length, ROW.length);
  });

  it("appends run to an existing all-match condition list and refuses an any-match one", async () => {
    const f = fakeFetch({ body: { events: [] } });
    const c = client(f.fetch);
    await c.queryEvents({
      advanced: { match: "all", conditions: [{ field: "sink", op: "contains", value: "sql" }] },
      run: "r1",
    });
    assert.equal(JSON.parse(f.calls[0]!.body!).advanced.conditions.length, 2);
    await assert.rejects(c.queryEvents({ advanced: { match: "any", conditions: [] }, run: "r1" }), TypeError);
  });

  it("reads a short row without failing", () => {
    const e = eventFromRow(["2026-07-05T12:00:00Z", "os system"]);
    assert.equal(e.where, "os system");
    assert.equal(e.id, 0);
    assert.deepEqual(e.labels, []);
    assert.equal(e.suppressed, false);
  });

  it("iterates past empty pages until the cursor is empty", async () => {
    const f = fakeFetch(
      { body: { events: [ROW], next_cursor: "c1" } },
      { body: { events: [], next_cursor: "c2" } },
      { body: { events: [ROW, ROW], next_cursor: "" } },
    );
    const seen = [];
    for await (const e of client(f.fetch).iterEvents({ severity: ["critical"] })) seen.push(e.id);
    assert.equal(seen.length, 3);
    assert.equal(f.calls.length, 3);
    assert.equal(JSON.parse(f.calls[1]!.body!).cursor, "c1");
    assert.equal(JSON.parse(f.calls[2]!.body!).cursor, "c2");
    assert.deepEqual(JSON.parse(f.calls[2]!.body!).severity, ["critical"]);
  });

  it("stops after maxPages, and on a cursor that does not move", async () => {
    const f = fakeFetch({ body: { events: [ROW], next_cursor: "c1" } }, { body: { events: [ROW], next_cursor: "c1" } });
    let n = 0;
    for await (const _ of client(f.fetch).iterEvents()) n++;
    assert.equal(n, 2);
    const g = fakeFetch({ body: { events: [ROW], next_cursor: "c1" } });
    n = 0;
    for await (const _ of client(g.fetch).iterEvents({ maxPages: 1 })) n++;
    assert.equal(n, 1);
    assert.equal(g.calls.length, 1);
  });

  it("forces the python view on the map and reads focus rows", async () => {
    const f = fakeFetch({ body: { events: 1, hits: 1, sources: [], files: [], sinks: [], links: [], focus: { events: [ROW], truncated: false } } });
    const m = await client(f.fetch).getEventMap({ file: "", sink: "os system", from: "2026-07-01" });
    const c = f.calls[0]!;
    assert.equal(c.url.searchParams.get("file"), "");
    assert.equal(c.url.searchParams.get("sink"), "os system");
    assert.deepEqual(JSON.parse(c.body!), { view: "python", from: "2026-07-01" });
    assert.equal(m.focus?.events[0]?.id, 12345);
  });

  it("returns an export as text", async () => {
    const f = fakeFetch({ body: "id,created_at\n1,2026-07-05\n", headers: { "content-type": "text/csv" } });
    const csv = await client(f.fetch).exportEvents("csv", { view: "browser" });
    assert.match(csv, /^id,created_at/);
    assert.equal(f.calls[0]!.url.searchParams.get("format"), "csv");
  });

  it("pages runs and activity", async () => {
    const f = fakeFetch(
      { body: { runs: [{ run_uid: "a" }], next_before: "b1" } },
      { body: { runs: [{ run_uid: "b" }], next_before: "" } },
      { body: { entries: [{ time: "2026-07-16T06:20:00Z", id: 9, action: "auth.login" }] } },
      { body: { entries: [] } },
    );
    const c = client(f.fetch);
    const runs = [];
    for await (const r of c.iterRuns({ machine: "web-01", limit: 1 })) runs.push(r.run_uid);
    assert.deepEqual(runs, ["a", "b"]);
    assert.equal(f.calls[1]!.url.searchParams.get("before"), "b1");
    const acts = [];
    for await (const a of c.iterActivity({ outcome: "success" })) acts.push(a.id);
    assert.deepEqual(acts, [9]);
    assert.equal(f.calls[3]!.url.searchParams.get("before_id"), "9");
    assert.equal(f.calls[3]!.url.searchParams.get("before_ts"), "2026-07-16T06:20:00Z");
  });
});

describe("machines, rules and triage", () => {
  it("reads machine rows by position", async () => {
    const f = fakeFetch({
      body: {
        machines: [
          ["2026-07-01T00:00:00Z", "web-01", "installed", "pid", "ubuntu_24_04_x86_64", "b1", "b2", "3.13", false, false, false, true, "python"],
        ],
      },
    });
    const [m] = await client(f.fetch).listMachines();
    assert.equal(m!.public_id, "pid");
    assert.equal(m!.stale_agent, true);
    assert.equal(m!.agent_kind, "python");
  });

  it("sends add_new_machine as a form, leaving out what was not given", async () => {
    const f = fakeFetch({ body: { Name: "web-01", PublicID: "pid", AgentKind: "python" } });
    await client(f.fetch).addMachine("web-01", { distro: "ubuntu_24_04", arch: "x86_64" });
    const c = f.calls[0]!;
    assert.equal(c.headers["Content-Type"], "application/x-www-form-urlencoded");
    assert.deepEqual(Object.fromEntries(new URLSearchParams(c.body)), {
      machine_name: "web-01",
      distro: "ubuntu_24_04",
      arch: "x86_64",
    });
  });

  it("sends attested as true on the CI install form", async () => {
    const f = fakeFetch({ body: { secret: "s", server_time: "2026-10-07T12:00:00Z" } });
    await client(f.fetch).ciInstall("ci-myrepo", { attested: true, distro: "ubuntu_24_04", arch: "x86_64" });
    const form = new URLSearchParams(f.calls[0]!.body);
    assert.equal(form.get("attested"), "true");
    assert.equal(form.get("machine_name"), "ci-myrepo");
  });

  it("accepts a Date, a string or Unix seconds as since", async () => {
    const f = fakeFetch({ body: {} }, { body: {} });
    const c = client(f.fetch);
    await c.ciFindings("ci", 1760000000.9, { min_severity: "critical" });
    await c.ciFindings("ci", new Date("2026-10-07T12:00:00Z"));
    assert.equal(f.calls[0]!.url.searchParams.get("since"), "1760000000");
    assert.equal(f.calls[0]!.url.searchParams.get("min_severity"), "critical");
    assert.equal(f.calls[1]!.url.searchParams.get("since"), "2026-10-07T12:00:00.000Z");
  });

  it("puts rules in the global scope unless a machine is named", async () => {
    const f = fakeFetch({ status: 201, body: { ID: 12, Mode: 1 } }, { body: { rules: [] } });
    const c = client(f.fetch);
    const r = await c.createRule({ event_pattern: "noise", mode: RuleMode.HIDE, label: "hide noise" });
    assert.equal(r.ID, 12);
    assert.deepEqual(JSON.parse(f.calls[0]!.body!), { machine: "", event_pattern: "noise", mode: 1, label: "hide noise" });
    await c.listRules();
    assert.equal(f.calls[1]!.url.searchParams.get("machine"), "");
  });

  it("treats a 204 as done", async () => {
    const f = fakeFetch({ status: 204 }, { status: 204 }, { status: 204 });
    const c = client(f.fetch);
    assert.equal(await c.attachLabel(1, 2), undefined);
    assert.equal(await c.setNote(1, "looks like a false positive"), undefined);
    assert.equal(await c.setEventUniqueness("python", null, "pid"), undefined);
    assert.equal(f.calls[0]!.url.pathname, "/api/event/1/labels/");
    assert.deepEqual(JSON.parse(f.calls[0]!.body!), { label_id: 2 });
    assert.equal(f.calls[1]!.method, "PUT");
    assert.deepEqual(JSON.parse(f.calls[2]!.body!), { agent_kind: "python", machine: "pid" });
  });

  it("rejects an id that is not an integer without sending anything", async () => {
    const f = fakeFetch();
    await assert.rejects(client(f.fetch).getEvent(1.5), TypeError);
    assert.equal(f.calls.length, 0);
  });

  it("switches to a newly generated key", async () => {
    const f = fakeFetch({ body: { api_key: "es2_NEW" } }, { body: {} });
    const c = client(f.fetch);
    const k = await c.generateApiKey({ password: "pw", expires: new Date("2027-01-01T00:00:00Z"), readOnly: true });
    assert.equal(k, "es2_NEW");
    const form = new URLSearchParams(f.calls[0]!.body);
    assert.equal(form.get("expires"), "2027-01-01");
    assert.equal(form.get("read_only"), "1");
    assert.equal(form.get("totp"), null);
    await c.getAccount();
    assert.equal(f.calls[1]!.headers["X-API-Key"], "es2_NEW");
  });
});

describe("errors and retries", () => {
  it("maps a status to its error class with the server's message", async () => {
    const f = fakeFetch(
      { status: 404, body: '{"error":"not found"}', headers: { "content-type": "text/plain" } },
      { status: 403, body: { error: "this API key is read-only" } },
      { status: 401, body: { error: "invalid or expired API key" } },
      { status: 409, body: "machine limit reached\n" },
    );
    const c = client(f.fetch);
    await assert.rejects(c.getEvent(7), (e: unknown) => {
      assert.ok(e instanceof NotFoundError);
      assert.equal(e.status, 404);
      assert.equal(e.serverMessage, "not found");
      assert.equal(e.path, "/api/event/7");
      return true;
    });
    await assert.rejects(c.createLabel("x"), PermissionDeniedError);
    await assert.rejects(c.getAccount(), AuthenticationError);
    await assert.rejects(c.addMachine("x"), (e: unknown) => e instanceof ConflictError && e.serverMessage === "machine limit reached");
  });

  it("never puts an HTML page in a message", async () => {
    const f = fakeFetch({ status: 404, body: "<!doctype html><title>x</title>", headers: { "content-type": "text/html" } });
    await assert.rejects(client(f.fetch).getAccount(), (e: unknown) => e instanceof NotFoundError && e.serverMessage === "");
  });

  it("waits out a 429 and tries again", async () => {
    const f = fakeFetch({ status: 429, body: { error: "slow down" }, headers: { "retry-after": "0" } }, { body: { username: "a" } });
    assert.equal((await client(f.fetch).getAccount()).username, "a");
    assert.equal(f.calls.length, 2);
  });

  it("gives up after maxRetries and reports Retry-After", async () => {
    const r = { status: 429, body: { error: "slow down" }, headers: { "retry-after": "0" } };
    const f = fakeFetch(r, r, r);
    await assert.rejects(client(f.fetch).getAccount(), (e: unknown) => e instanceof RateLimitError && e.retryAfter === 0);
    assert.equal(f.calls.length, 3);
  });

  it("does not retry a password-checked account call into a lockout", async () => {
    const f = fakeFetch({ status: 429, body: { error: "locked" }, headers: { "retry-after": "0" } });
    await assert.rejects(client(f.fetch).revokeApiKey({ password: "pw" }), RateLimitError);
    assert.equal(f.calls.length, 1);
  });

  it("retries a read after a 503 or a dropped connection, never a write", async () => {
    const f = fakeFetch({ status: 503, body: "busy" }, new TypeError("fetch failed"), { body: { events: [] } });
    await client(f.fetch).queryEvents();
    assert.equal(f.calls.length, 3);

    const g = fakeFetch({ status: 503, body: "busy" });
    await assert.rejects(client(g.fetch).createLabel("x"), (e: unknown) => e instanceof Error && (e as { status?: number }).status === 503);
    assert.equal(g.calls.length, 1);

    const h = fakeFetch(new TypeError("fetch failed"));
    await assert.rejects(client(h.fetch).deleteMachine("pid"), (e: unknown) => {
      assert.ok(e instanceof APIConnectionError);
      assert.ok(!(e instanceof APITimeoutError));
      assert.match(e.message, /could not reach https:\/\/example\.test/);
      return true;
    });
    assert.equal(h.calls.length, 1);
  });

  it("times out", async () => {
    const hang: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const c = new EyalSec({ apiKey: KEY, baseUrl: "https://example.test", fetch: hang, timeout: 20, maxRetries: 0 });
    await assert.rejects(c.getAccount(), APITimeoutError);
  });

  it("refuses to follow a redirect", async () => {
    const f = fakeFetch({ status: 302, headers: { location: "/login/" } });
    await assert.rejects(client(f.fetch).getAccount(), UnexpectedResponseError);
  });

  it("reports a body that is not JSON", async () => {
    const f = fakeFetch({ body: "not json", headers: { "content-type": "text/plain" } });
    await assert.rejects(client(f.fetch).getAccount(), UnexpectedResponseError);
  });
});
