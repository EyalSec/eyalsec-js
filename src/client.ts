import {
  APIConnectionError,
  APITimeoutError,
  ConfigurationError,
  UnexpectedResponseError,
  errorClassFor,
} from "./errors.js";
import { eventFromRow, machineFromRow } from "./rows.js";
import type {
  Account,
  ActivityEntry,
  ActivityOptions,
  ActivityPage,
  AddMachineOptions,
  APIKeyInfo,
  BlockClientOptions,
  BlockedClient,
  CIFindings,
  CIFindingsOptions,
  CIInstall,
  CIInstallOptions,
  CreateFilterOptions,
  CreateRuleOptions,
  DateInput,
  Distro,
  Egress,
  EgressRule,
  Event,
  EventCount,
  EventDetail,
  EventFilters,
  EventMap,
  EventMapOptions,
  EventPage,
  EventStats,
  EventUniqueness,
  ExportFormat,
  Filter,
  FilterMode,
  InstallCommand,
  Label,
  LabelColor,
  ListRunsOptions,
  Machine,
  NewMachine,
  OnboardingState,
  PythonVersions,
  Reauth,
  RouteStats,
  Rule,
  RuleTemplate,
  RuleTemplateList,
  Run,
  RunPage,
  SavedSearch,
  SelftestStatus,
  SetEgressOptions,
  StatusAnswer,
  TaintState,
  TemplateApplyResult,
  TemplateItem,
  UniquenessAxis,
  UpdateFilterOptions,
  UpdateRuleOptions,
  View,
  ViewCountsOptions,
  VisibilityCounts,
  WebProtection,
} from "./types.js";
import { VERSION } from "./version.js";

export const DEFAULT_BASE_URL = "https://eyalsec.com";
export const API_KEY_ENV = "EYALSEC_API_KEY";
export const BASE_URL_ENV = "EYALSEC_URL";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 2;
const MAX_RETRY_WAIT_S = 60;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/** Reads that are POSTs because their filters travel in the body: safe to retry. */
const IDEMPOTENT_POSTS = new Set(["/api/get_all_events_with_count/", "/api/event_map/", "/api/events_export"]);

/** The subset of `fetch` the client uses, so you can pass your own. */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    redirect: "manual";
    signal: AbortSignal;
  },
) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}>;

export interface ClientOptions {
  /** Your API key (it starts with `es2_`). Defaults to the `EYALSEC_API_KEY` environment variable. */
  apiKey?: string;
  /** Your EyalSec address. Defaults to `EYALSEC_URL`, then `https://eyalsec.com`. */
  baseUrl?: string;
  /** Milliseconds before a request is abandoned. Default 30000. */
  timeout?: number;
  /** Retries after a rate limit, or after a dropped connection on a read. Default 2. */
  maxRetries?: number;
  /** Your own `fetch`, for proxies, custom TLS or tests. Defaults to the global `fetch`. */
  fetch?: FetchLike;
  /** Added to the `User-Agent` header, such as `my-report/1.2`. */
  userAgent?: string;
}

type Query = Record<string, string | number | boolean | undefined | null>;

interface RequestSpec {
  query?: Query;
  json?: unknown;
  form?: Query;
  /** Needs no API key. */
  public?: boolean;
  /** Return the body as text instead of parsing JSON. */
  text?: boolean;
}

function env(name: string): string | undefined {
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return p?.env?.[name];
}

function normalizeBaseUrl(url: string | undefined): string {
  const raw = (url ?? env(BASE_URL_ENV) ?? "").trim().replace(/\/+$/, "");
  if (!raw) return DEFAULT_BASE_URL;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ConfigurationError(`baseUrl must be an https:// address, got ${JSON.stringify(raw)}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new ConfigurationError(`baseUrl must be an https:// address, got ${JSON.stringify(raw)}`);
  }
  if (parsed.protocol === "http:" && !LOCAL_HOSTS.has(parsed.hostname)) {
    throw new ConfigurationError(
      `baseUrl must use https:// (the API key would be sent in clear text), got ${JSON.stringify(raw)}`,
    );
  }
  return raw;
}

function dateString(v: DateInput): string {
  return v instanceof Date ? v.toISOString() : String(v);
}

function list<T>(v: T | T[] | undefined): T[] | undefined {
  if (v === undefined) return undefined;
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    return v
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean) as unknown as T[];
  }
  return [v];
}

function defined<T extends Record<string, unknown>>(o: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) out[k] = v;
  return out as Partial<T>;
}

/** Build the JSON body shared by the events query, the export and the map. */
export function eventFiltersBody(f: EventFilters = {}): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (f.view) body.view = f.view;
  if (f.bucket) body.bucket = f.bucket;
  if (f.sort) body.sort = f.sort;
  if (f.from !== undefined) body.from = dateString(f.from);
  if (f.to !== undefined) body.to = dateString(f.to);
  if (f.machine) body.machine = f.machine;
  const severity = list(f.severity);
  if (severity) body.severity = severity;
  const sources = list(f.sources);
  if (sources) body.sources = sources;
  const tags = list(f.tags);
  if (tags) body.tags = tags;
  if (f.labels) body.labels = f.labels.map(Number);
  if (f.whitelist_repr) body.whitelist_repr = f.whitelist_repr;
  if (f.blacklist_repr) body.blacklist_repr = f.blacklist_repr;
  if (f.xss_only !== undefined) body.xss_only = Boolean(f.xss_only);
  if (f.scope) body.scope = { ...f.scope };
  let advanced = f.advanced ? { ...f.advanced, conditions: [...(f.advanced.conditions ?? [])] } : undefined;
  if (f.run) {
    if (!advanced) advanced = { match: "all", conditions: [] };
    else if ((advanced.match ?? "all") !== "all") {
      throw new TypeError('run needs advanced.match "all"; add the run condition to advanced yourself');
    }
    advanced.conditions.push({ field: "run", op: "is", value: f.run });
  }
  if (advanced) body.advanced = advanced;
  if (f.extra) Object.assign(body, f.extra);
  return body;
}

function parseRetryAfter(v: string | null): number | undefined {
  if (!v) return undefined;
  const s = v.trim();
  if (/^\d+(\.\d+)?$/.test(s)) return Math.max(0, Number(s));
  const when = Date.parse(s);
  if (Number.isNaN(when)) return undefined;
  return Math.max(0, (when - Date.now()) / 1000);
}

function retryWaitMs(attempt: number, retryAfter: number | undefined): number {
  if (retryAfter !== undefined) return Math.min(retryAfter, MAX_RETRY_WAIT_S) * 1000;
  const base = Math.min(0.5 * 2 ** (attempt - 1), 8);
  return (base + Math.random() * (base / 4)) * 1000;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function machineParam(machine: string | null | undefined): string {
  return machine ?? "";
}

function intId(name: string, v: number): number {
  if (!Number.isInteger(v)) throw new TypeError(`${name} must be an integer, got ${String(v)}`);
  return v;
}

function encodeQuery(q: Query | undefined): string {
  if (!q) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null) continue;
    p.append(k, typeof v === "boolean" ? (v ? "true" : "false") : String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

/**
 * Client for the EyalSec API.
 *
 * ```ts
 * import { EyalSec } from "eyalsec";
 * const client = new EyalSec(); // reads EYALSEC_API_KEY
 * for await (const event of client.iterEvents({ severity: ["critical", "high"] })) {
 *   console.log(event.severity, event.where, event.machine_name);
 * }
 * ```
 *
 * Every method returns a promise. Errors are thrown as {@link EyalSecError}
 * subclasses; see `errors.ts`.
 */
export class EyalSec {
  readonly baseUrl: string;
  readonly maxRetries: number;
  readonly timeout: number;
  #apiKey: string;
  #fetch: FetchLike;
  #userAgent: string;

  constructor(options: ClientOptions = {}) {
    this.#apiKey = (options.apiKey ?? env(API_KEY_ENV) ?? "").trim();
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = Math.max(0, Math.floor(options.maxRetries ?? DEFAULT_MAX_RETRIES));
    const f = options.fetch ?? (globalThis.fetch as unknown as FetchLike | undefined);
    if (!f) {
      throw new ConfigurationError("No fetch available. Use Node.js 18 or newer, or pass options.fetch.");
    }
    this.#fetch = f;
    this.#userAgent = `eyalsec-js/${VERSION}` + (options.userAgent ? ` ${options.userAgent}` : "");
  }

  /** Whether an API key is set. The key itself is never exposed. */
  get hasApiKey(): boolean {
    return this.#apiKey !== "";
  }

  /** @internal Keeps the key out of `console.log(client)` and `JSON.stringify(client)`. */
  toJSON(): Record<string, unknown> {
    return { baseUrl: this.baseUrl, timeout: this.timeout, maxRetries: this.maxRetries };
  }

  // ---------------------------------------------------------------- transport

  async #request<T = unknown>(method: string, path: string, spec: RequestSpec = {}): Promise<T> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": this.#userAgent,
    };
    if (!spec.public) {
      if (!this.#apiKey) {
        throw new ConfigurationError(
          `No API key. Pass { apiKey } or set ${API_KEY_ENV}. Create a key on your EyalSec dashboard under ` +
            "Settings > API access (a read-only key is enough for reads).",
        );
      }
      headers["X-API-Key"] = this.#apiKey;
    }
    let body: string | undefined;
    if (spec.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(spec.json);
    } else if (spec.form) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = encodeQuery(spec.form).replace(/^\?/, "");
    }
    const idempotent =
      method === "GET" || method === "PUT" || method === "DELETE" || (method === "POST" && IDEMPOTENT_POSTS.has(path));
    // A 429 on a password-checked account call can be a sign-in lockout that
    // lasts minutes: report it rather than retrying into it.
    const retry429 = !(method === "POST" && path.startsWith("/api/account/"));
    const url = this.baseUrl + path + encodeQuery(spec.query);

    for (let attempt = 1; ; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);
      let resp: Awaited<ReturnType<FetchLike>>;
      let text: string;
      try {
        resp = await this.#fetch(url, {
          method,
          headers,
          ...(body !== undefined ? { body } : {}),
          redirect: "manual",
          signal: controller.signal,
        });
        text = await resp.text();
      } catch (err) {
        clearTimeout(timer);
        if (idempotent && attempt <= this.maxRetries) {
          await sleep(retryWaitMs(attempt, undefined));
          continue;
        }
        if (controller.signal.aborted) {
          throw new APITimeoutError(`${method} ${path} timed out after ${this.timeout} ms talking to ${this.baseUrl}`, err);
        }
        const detail = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
        throw new APIConnectionError(`${method} ${path}: could not reach ${this.baseUrl} (${detail})`, err);
      }
      clearTimeout(timer);

      const status = resp.status;
      if (
        attempt <= this.maxRetries &&
        ((status === 429 && retry429) || (idempotent && (status === 502 || status === 503 || status === 504)))
      ) {
        const wait = parseRetryAfter(resp.headers.get("retry-after"));
        if (wait === undefined || wait <= MAX_RETRY_WAIT_S) {
          await sleep(retryWaitMs(attempt, wait));
          continue;
        }
      }

      const ctype = resp.headers.get("content-type") ?? "";
      if (status >= 300 && status < 400) {
        throw new UnexpectedResponseError(
          status,
          `unexpected redirect to ${resp.headers.get("location") ?? "?"}; check baseUrl`,
          { method, path },
        );
      }
      if (status >= 400) {
        let parsed: unknown;
        let message = "";
        // Some endpoints send a JSON error body without a JSON content type.
        if (ctype.includes("json") || text.trimStart().startsWith("{")) {
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = undefined;
          }
          if (parsed && typeof parsed === "object") {
            const o = parsed as Record<string, unknown>;
            for (const k of ["error", "message", "detail"]) {
              if (o[k]) {
                message = String(o[k]).slice(0, 1000);
                break;
              }
            }
          }
        }
        if (!message && !ctype.includes("html") && !text.trimStart().startsWith("<")) {
          message = text.trim().slice(0, 1000);
        }
        const Cls = errorClassFor(status);
        throw new Cls(status, message, {
          method,
          path,
          body: parsed,
          retryAfter: parseRetryAfter(resp.headers.get("retry-after")),
        });
      }
      if (spec.text) return text as T;
      if (status === 204 || text.trim() === "") return {} as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new UnexpectedResponseError(status, "the answer was not JSON", { method, path });
      }
    }
  }

  async #object<T>(method: string, path: string, spec?: RequestSpec): Promise<T> {
    const v = await this.#request<unknown>(method, path, spec);
    if (typeof v !== "object" || v === null || Array.isArray(v)) {
      throw new UnexpectedResponseError(200, "expected a JSON object", { method, path, body: v });
    }
    return v as T;
  }

  async #void(method: string, path: string, spec?: RequestSpec): Promise<void> {
    await this.#request(method, path, spec);
  }

  // ---------------------------------------------------------------- events

  /**
   * One page (up to 100) of your events, newest first unless `sort` says otherwise.
   *
   * A short or empty page is not the last page: pass `next_cursor` back as
   * `cursor`, with the same filters, until it comes back empty. Or use
   * {@link iterEvents}, which does that for you.
   */
  async queryEvents(options: EventFilters & { cursor?: string } = {}): Promise<EventPage> {
    const { cursor, ...filters } = options;
    const body = eventFiltersBody(filters);
    if (cursor) body.cursor = cursor;
    const d = await this.#object<Record<string, unknown>>("POST", "/api/get_all_events_with_count/", { json: body });
    const rows = Array.isArray(d.events) ? d.events : [];
    return {
      ...d,
      events: rows.map(eventFromRow),
      next_cursor: typeof d.next_cursor === "string" ? d.next_cursor : "",
      scanned: Number(d.scanned ?? 0),
      exhausted: Boolean(d.exhausted),
      oldest_examined: typeof d.oldest_examined === "string" ? d.oldest_examined : "",
      event_limit: Number(d.event_limit ?? 0),
      event_limit_monthly: Boolean(d.event_limit_monthly),
    } as EventPage;
  }

  /**
   * Every event matching the filters, following the cursor, including past
   * empty pages (each request examines a bounded slice of history, so a
   * selective filter can return an empty page with matches further back).
   * `maxPages` stops after that many requests.
   */
  async *iterEvents(options: EventFilters & { maxPages?: number } = {}): AsyncGenerator<Event, void, undefined> {
    const { maxPages, ...filters } = options;
    let cursor: string | undefined;
    for (let pages = 1; ; pages++) {
      const page = await this.queryEvents({ ...filters, ...(cursor ? { cursor } : {}) });
      yield* page.events;
      if (!page.next_cursor || page.next_cursor === cursor) return;
      if (maxPages !== undefined && pages >= maxPages) return;
      cursor = page.next_cursor;
    }
  }

  /** One event's stack trace, origin, source listings, your note and the runs that produced it. */
  async getEvent(eventId: number): Promise<EventDetail> {
    return this.#object("GET", `/api/event/${intId("eventId", eventId)}`);
  }

  /** One page of the runs behind your events, newest first. */
  async listRuns(options: ListRunsOptions = {}): Promise<RunPage> {
    const d = await this.#object<Record<string, unknown>>("GET", "/api/runs/", {
      query: { machine: options.machine, q: options.q, before: options.before || undefined, limit: options.limit },
    });
    return {
      ...d,
      runs: Array.isArray(d.runs) ? (d.runs as Run[]) : [],
      next_before: typeof d.next_before === "string" ? d.next_before : "",
    };
  }

  /** Every run, following `next_before`. */
  async *iterRuns(
    options: Omit<ListRunsOptions, "before"> & { maxPages?: number } = {},
  ): AsyncGenerator<Run, void, undefined> {
    const { maxPages, ...rest } = options;
    let before: string | undefined;
    for (let pages = 1; ; pages++) {
      const page = await this.listRuns({ ...rest, ...(before ? { before } : {}) });
      yield* page.runs;
      if (!page.next_before || page.next_before === before) return;
      if (maxPages !== undefined && pages >= maxPages) return;
      before = page.next_before;
    }
  }

  /** The dashboard's summary: totals, recent counts, top event types and a 14-day timeline. */
  async getEventStats(): Promise<EventStats> {
    return this.#object("GET", "/api/get_event_stats/");
  }

  /** How many stored events count toward your quota, with your limit. Pass a `view` for one product's number. */
  async getEventCount(view?: View): Promise<EventCount> {
    return this.#object("GET", "/api/event_count/", { query: { view } });
  }

  /** How many events each product's list would show, such as `{ python: 1204, browser: 38 }`. */
  async getEventViewCounts(options: ViewCountsOptions = {}): Promise<Record<string, number>> {
    return this.#object("GET", "/api/event_view_counts/", { query: { ...options } });
  }

  /** How many stored events are shown (`live`) and how many the sanitizer hides (`suppressed`). */
  async getEventVisibilityCounts(): Promise<VisibilityCounts> {
    return this.#object("GET", "/api/event_visibility_counts/");
  }

  /**
   * Every event matching the filters as one CSV or JSON document (up to
   * 50,000 rows; the file says when it stopped). Returns the text.
   */
  async exportEvents(format: ExportFormat = "csv", filters: EventFilters = {}): Promise<string> {
    return this.#request<string>("POST", "/api/events_export", {
      query: { format },
      json: eventFiltersBody(filters),
      text: true,
    });
  }

  /** Your es-python events as a graph of sources, files and sinks. The view is always `python`. */
  async getEventMap(options: EventMapOptions = {}): Promise<EventMap> {
    const { source, file, sink, only, ...filters } = options;
    const d = await this.#object<Record<string, unknown>>("POST", "/api/event_map/", {
      query: { source, file, sink, only },
      json: eventFiltersBody({ ...filters, view: "python" }),
    });
    const focus = d.focus as { events?: unknown; truncated?: unknown } | undefined;
    if (focus && typeof focus === "object") {
      d.focus = {
        ...focus,
        events: Array.isArray(focus.events) ? focus.events.map(eventFromRow) : [],
        truncated: Boolean(focus.truncated),
      };
    }
    return d as EventMap;
  }

  /** The distinct sink labels (`where`) across your events. */
  async listEventNames(): Promise<string[]> {
    const d = await this.#object<{ names?: unknown }>("GET", "/api/event_names/");
    return Array.isArray(d.names) ? d.names.map(String) : [];
  }

  /** Your saved searches for one product. */
  async listSavedSearches(view: View = "python"): Promise<SavedSearch[]> {
    const d = await this.#object<{ searches?: SavedSearch[] }>("GET", "/api/event_searches/", { query: { view } });
    return d.searches ?? [];
  }

  /** Save a named events-page query string (without the leading `?`). Returns that product's whole list. */
  async saveSearch(name: string, query: string, view: View = "python"): Promise<SavedSearch[]> {
    const d = await this.#object<{ searches?: SavedSearch[] }>("POST", "/api/event_searches/", {
      json: { name, view, query },
    });
    return d.searches ?? [];
  }

  async deleteSavedSearch(searchId: number): Promise<void> {
    return this.#void("DELETE", `/api/event_searches/${intId("searchId", searchId)}`);
  }

  // ---------------------------------------------------------------- machines

  /** Every machine on your account. */
  async listMachines(): Promise<Machine[]> {
    const d = await this.#object<{ machines?: unknown }>("GET", "/api/get_all_machines/");
    return Array.isArray(d.machines) ? d.machines.map(machineFromRow) : [];
  }

  /**
   * Register a new machine. For es-python, leave `distro` and `arch` out to
   * have the build detected when the install runs. At your machine limit
   * this throws {@link ConflictError}.
   */
  async addMachine(machineName: string, options: AddMachineOptions = {}): Promise<NewMachine> {
    return this.#object("POST", "/api/add_new_machine/", { form: { machine_name: machineName, ...options } });
  }

  /** Change the distribution and architecture a machine is installed for. */
  async setMachineOs(machineName: string, distro: string, arch: string): Promise<{ machine_name: string; os_type: string }> {
    return this.#object("POST", "/api/set_machine_os/", { form: { machine_name: machineName, distro, arch } });
  }

  async renameMachine(publicId: string, machineName: string): Promise<{ public_id: string; machine_name: string }> {
    return this.#object("POST", "/api/rename_machine/", { json: { public_id: publicId, machine_name: machineName } });
  }

  /** Delete a machine **and every event it reported**. Cannot be undone. */
  async deleteMachine(publicId: string): Promise<void> {
    return this.#void("POST", "/api/delete_machine/", { json: { public_id: publicId } });
  }

  /**
   * Issue a one-time install secret for an es-python machine. `attested: true`
   * is your confirmation that you are authorized to monitor that machine, the
   * same box the dashboard asks you to tick.
   */
  async getInstallCommand(publicId: string, options: { attested: boolean; renew?: boolean }): Promise<InstallCommand> {
    return this.#object("POST", "/api/get_eyalsec_install_script_data/", {
      json: defined({ public_id: publicId, attested: Boolean(options.attested), renew: options.renew }),
    });
  }

  /** Issue a one-time secret for removing es-python from a machine. */
  async getUninstallCommand(publicId: string): Promise<InstallCommand> {
    return this.#object("POST", "/api/get_uninstall_script_data/", { json: { public_id: publicId } });
  }

  /** The distributions and architectures es-python installs on. Needs no API key. */
  async listSupportedOsTypes(): Promise<Distro[]> {
    const d = await this.#object<{ distros?: Distro[] }>("GET", "/api/supported_os_types/", { public: true });
    return d.distros ?? [];
  }

  /** The Python versions you can pick, and the default; pass an `os_type` for one target. Needs no API key. */
  async listSupportedPythonVersions(osType?: string): Promise<PythonVersions> {
    return this.#object("GET", "/api/supported_python_versions/", { query: { os: osType }, public: true });
  }

  // ---------------------------------------------------------------- CI

  /**
   * A one-time install secret for a CI runner's machine, found by name and
   * created the first time (`distro` and `arch` are then required). Call it
   * once per pipeline run.
   */
  async ciInstall(machineName: string, options: CIInstallOptions & { attested: boolean }): Promise<CIInstall> {
    const { attested, ...rest } = options;
    return this.#object("POST", "/api/ci/install/", {
      form: { machine_name: machineName, attested: Boolean(attested), ...rest },
    });
  }

  /**
   * What runs on one machine reported since a moment. `since` is a `Date`,
   * an RFC 3339 string or Unix seconds; prefer the server's clock
   * (`CIInstall.server_time`) to the runner's.
   */
  async ciFindings(machine: string, since: Date | string | number, options: CIFindingsOptions = {}): Promise<CIFindings> {
    const s = typeof since === "number" ? String(Math.floor(since)) : dateString(since);
    return this.#object("GET", "/api/ci/findings/", { query: { machine, since: s, ...options } });
  }

  // ---------------------------------------------------------------- filters

  /** Your event filters, or only those shown on one product's Filters page. */
  async listFilters(engine?: string): Promise<Filter[]> {
    const d = await this.#object<{ filters?: Filter[] }>("GET", "/api/filters/", { query: { engine } });
    return d.filters ?? [];
  }

  /** Add an event filter: `blacklist` hides matches, `whitelist` shows only them. */
  async createFilter(pattern: string, mode: FilterMode, options: CreateFilterOptions = {}): Promise<Filter> {
    return this.#object("POST", "/api/filters/create/", { json: defined({ pattern, mode, ...options }) });
  }

  /** Change a filter; send only what changes. */
  async updateFilter(filterId: number, changes: UpdateFilterOptions): Promise<Filter> {
    return this.#object("PATCH", `/api/filters/${intId("filterId", filterId)}/update/`, { json: defined({ ...changes }) });
  }

  async deleteFilter(filterId: number): Promise<void> {
    return this.#void("DELETE", `/api/filters/${intId("filterId", filterId)}/delete/`);
  }

  // ---------------------------------------------------------------- rules

  /** The rules in one scope: a machine's `public_id`, or omit for your global rules. */
  async listRules(machine?: string): Promise<Rule[]> {
    const d = await this.#object<{ rules?: Rule[] }>("GET", "/api/machine_rules/", {
      query: { machine: machineParam(machine) },
    });
    return d.rules ?? [];
  }

  /**
   * Add a rule. A Raise rule (mode 3) needs Raise enabled for your account
   * (`grant_raise` on {@link getAccount}); otherwise it is refused with 403.
   */
  async createRule(options: CreateRuleOptions = {}): Promise<Rule> {
    const { machine, ...rest } = options;
    return this.#object("POST", "/api/machine_rules/create/", {
      json: defined({ machine: machineParam(machine), ...rest }),
    });
  }

  async updateRule(ruleId: number, changes: UpdateRuleOptions): Promise<Rule> {
    return this.#object("PATCH", `/api/machine_rules/${intId("ruleId", ruleId)}/update/`, {
      json: defined({ ...changes }),
    });
  }

  async deleteRule(ruleId: number): Promise<void> {
    return this.#void("DELETE", `/api/machine_rules/${intId("ruleId", ruleId)}/delete/`);
  }

  // ---------------------------------------------------------------- taint

  /** Every taint setting for one scope: `on`, `off` or `unset` (inherit). */
  async getTaint(machine?: string): Promise<Record<string, TaintState>> {
    const d = await this.#object<{ taint?: Record<string, TaintState> }>("GET", "/api/machine_taint/", {
      query: { machine: machineParam(machine) },
    });
    return d.taint ?? {};
  }

  /** Set one taint setting in one scope. es-python applies it when the program next starts. */
  async setTaint(source: string, state: TaintState, machine?: string): Promise<void> {
    return this.#void("PUT", "/api/machine_taint/", { json: { machine: machineParam(machine), source, state } });
  }

  // ---------------------------------------------------------------- web protection

  async getWebProtection(machine?: string): Promise<WebProtection> {
    return this.#object("GET", "/api/web_protection/", { query: { machine: machineParam(machine) } });
  }

  /** Store one web protection setting; an empty `value` clears it. */
  async setWebProtection(key: string, value: string, machine?: string): Promise<void> {
    return this.#void("PUT", "/api/web_protection/", { json: { machine: machineParam(machine), key, value } });
  }

  async listBlockedClients(): Promise<BlockedClient[]> {
    const d = await this.#object<{ entries?: BlockedClient[] }>("GET", "/api/web_protection/blocklist/");
    return d.entries ?? [];
  }

  async blockClient(address: string, options: BlockClientOptions = {}): Promise<BlockedClient> {
    return this.#object("POST", "/api/web_protection/blocklist/", { json: defined({ address, ...options }) });
  }

  async unblockClient(entryId: number): Promise<void> {
    return this.#void("DELETE", `/api/web_protection/blocklist/${intId("entryId", entryId)}/`);
  }

  async listRoutes(): Promise<RouteStats[]> {
    const d = await this.#object<{ routes?: RouteStats[] }>("GET", "/api/web_protection/routes/");
    return d.routes ?? [];
  }

  // ---------------------------------------------------------------- unique events

  /** The unique-event definition in force for one product (`agent_kind`, such as `python`) and scope. */
  async getEventUniqueness(agentKind: string, options: { machine?: string; event?: number } = {}): Promise<EventUniqueness> {
    return this.#object("GET", "/api/event_uniqueness/", {
      query: { agent_kind: agentKind, machine: machineParam(options.machine), event: options.event },
    });
  }

  /**
   * Set the definition for one product and scope. Pass `axes: null` to
   * remove this scope's own setting so it inherits again.
   */
  async setEventUniqueness(agentKind: string, axes: UniquenessAxis[] | null, machine?: string): Promise<void> {
    const body: Record<string, unknown> = { agent_kind: agentKind, machine: machineParam(machine) };
    if (axes !== null) body.axes = axes;
    return this.#void("PUT", "/api/event_uniqueness/", { json: body });
  }

  // ---------------------------------------------------------------- outbound connections

  /** The es-python outbound connections policy for your account, or for one machine. */
  async getEgress(machine?: string): Promise<Egress> {
    return this.#object("GET", "/api/egress/", { query: { machine: machine || undefined } });
  }

  /** Replace one scope's outbound settings and its whole rule list. A setting left `null` inherits. */
  async setEgress(rules: EgressRule[], options: SetEgressOptions = {}): Promise<Egress> {
    return this.#object("PUT", "/api/egress/", {
      json: {
        machine: machineParam(options.machine),
        mode: options.mode ?? null,
        default: options.default ?? null,
        on_violation: options.on_violation ?? null,
        rules,
      },
    });
  }

  // ---------------------------------------------------------------- rule templates

  /** Your own templates and the EyalSec ones, with the categories the Templates page lists them under. */
  async listRuleTemplates(): Promise<RuleTemplateList> {
    const d = await this.#object<Partial<RuleTemplateList>>("GET", "/api/rule_templates/");
    return { ...d, templates: d.templates ?? [], categories: d.categories ?? [] };
  }

  async createRuleTemplate(name: string, items: TemplateItem[], description?: string): Promise<RuleTemplate> {
    return this.#object("POST", "/api/rule_templates/create/", { json: defined({ name, description, items }) });
  }

  /** Rename one of your templates and replace its whole rule list. */
  async updateRuleTemplate(templateId: number, name: string, items: TemplateItem[], description?: string): Promise<void> {
    return this.#void("PATCH", `/api/rule_templates/${intId("templateId", templateId)}/update/`, {
      json: defined({ name, description, items }),
    });
  }

  async deleteRuleTemplate(templateId: number): Promise<void> {
    return this.#void("DELETE", `/api/rule_templates/${intId("templateId", templateId)}/delete/`);
  }

  /** Add a template's rules to a scope. Duplicates, and Raise items when Raise is not enabled, are skipped and counted. */
  async applyRuleTemplate(templateId: number, machine?: string): Promise<TemplateApplyResult> {
    return this.#object("POST", `/api/rule_templates/${intId("templateId", templateId)}/apply/`, {
      json: { machine: machineParam(machine) },
    });
  }

  /** Save the rules currently in a scope as a new template of your own. */
  async snapshotRuleTemplate(name: string, options: { machine?: string; description?: string } = {}): Promise<RuleTemplate> {
    return this.#object("POST", "/api/rule_templates/snapshot/", {
      json: defined({ name, description: options.description, machine: machineParam(options.machine) }),
    });
  }

  // ---------------------------------------------------------------- labels and notes

  async listLabels(): Promise<Label[]> {
    const d = await this.#object<{ labels?: Label[] }>("GET", "/api/event_labels/");
    return d.labels ?? [];
  }

  /** Create a label. A name you already use throws {@link ConflictError}. */
  async createLabel(name: string, color?: LabelColor): Promise<Label> {
    return this.#object("POST", "/api/event_labels/", { json: defined({ name, color }) });
  }

  /** Set a label's name and color. Both are written, so leaving `color` out sets it back to amber. */
  async updateLabel(labelId: number, name: string, color?: LabelColor): Promise<void> {
    return this.#void("PATCH", `/api/event_labels/${intId("labelId", labelId)}/`, { json: defined({ name, color }) });
  }

  async deleteLabel(labelId: number): Promise<void> {
    return this.#void("DELETE", `/api/event_labels/${intId("labelId", labelId)}/`);
  }

  async attachLabel(eventId: number, labelId: number): Promise<void> {
    return this.#void("POST", `/api/event/${intId("eventId", eventId)}/labels/`, {
      json: { label_id: intId("labelId", labelId) },
    });
  }

  async detachLabel(eventId: number, labelId: number): Promise<void> {
    return this.#void("DELETE", `/api/event/${intId("eventId", eventId)}/labels/${intId("labelId", labelId)}/`);
  }

  /** Set your note on an event (at most 4096 bytes). Read it back with {@link getEvent}. */
  async setNote(eventId: number, body: string): Promise<void> {
    return this.#void("PUT", `/api/event/${intId("eventId", eventId)}/comment/`, { json: { body } });
  }

  async deleteNote(eventId: number): Promise<void> {
    return this.#void("DELETE", `/api/event/${intId("eventId", eventId)}/comment/`);
  }

  // ---------------------------------------------------------------- activity

  /** One page (50) of your activity log, newest first. Entries are kept for 30 days. */
  async listActivity(options: ActivityOptions = {}): Promise<ActivityPage> {
    const d = await this.#object<Partial<ActivityPage>>("GET", "/api/activity/", { query: { ...options } });
    return { ...d, entries: d.entries ?? [] };
  }

  /** Every activity entry, following the pages. */
  async *iterActivity(
    options: Pick<ActivityOptions, "action" | "outcome"> & { maxPages?: number } = {},
  ): AsyncGenerator<ActivityEntry, void, undefined> {
    const { maxPages, ...rest } = options;
    let before: { ts: string; id: number } | undefined;
    for (let pages = 1; ; pages++) {
      const page = await this.listActivity({
        ...rest,
        ...(before ? { before_ts: before.ts, before_id: before.id } : {}),
      });
      yield* page.entries;
      const last = page.entries[page.entries.length - 1];
      if (!last) return;
      const next = { ts: last.time, id: last.id };
      if (before && next.ts === before.ts && next.id === before.id) return;
      if (maxPages !== undefined && pages >= maxPages) return;
      before = next;
    }
  }

  // ---------------------------------------------------------------- account

  /** Your profile, limits and permissions. */
  async getAccount(): Promise<Account> {
    return this.#object("GET", "/api/account/");
  }

  /** How far the account is in setting up es-python. */
  async getOnboardingState(): Promise<OnboardingState> {
    return this.#object("GET", "/api/onboarding_state/");
  }

  /** Set the time zone dates are shown in (an IANA name, or `""` for automatic). Returns the stored value. */
  async setTimezone(timezone: string): Promise<string> {
    const d = await this.#object<{ timezone?: string }>("POST", "/api/account/timezone", { form: { timezone } });
    return d.timezone ?? "";
  }

  /** Change or remove your recovery email. A new address applies only once the link sent to it is clicked. */
  async changeEmail(email: string, auth: Reauth): Promise<StatusAnswer> {
    return this.#object("POST", "/api/account/email", { form: { email, ...auth } });
  }

  /** Change your password. **This revokes your API key and every session**, including this client's key. */
  async changePassword(currentPassword: string, newPassword: string, totp?: string): Promise<StatusAnswer> {
    return this.#object("POST", "/api/account/password", {
      form: { current_password: currentPassword, new_password: newPassword, confirm: newPassword, totp },
    });
  }

  /** Delete your account and everything in it. There is no undo. */
  async deleteAccount(auth: Reauth): Promise<void> {
    return this.#void("POST", "/api/account/delete", { form: { ...auth } });
  }

  /** Start authenticator setup: a new `secret` and `otpauth_url`, held for 10 minutes. */
  async startTotpSetup(): Promise<{ secret: string; otpauth_url: string; expires_in_seconds: number; note?: string }> {
    return this.#object("GET", "/api/account/2fa/setup");
  }

  /** Finish authenticator setup with a code from the new secret. The answer holds your backup codes, shown once. */
  async enableTotp(password: string, totp: string): Promise<StatusAnswer & { backup_codes?: string[] }> {
    return this.#object("POST", "/api/account/2fa/enable", { form: { password, totp } });
  }

  async disableTotp(auth: Reauth): Promise<StatusAnswer> {
    return this.#object("POST", "/api/account/2fa/disable", { form: { ...auth } });
  }

  async regenerateBackupCodes(auth: Reauth): Promise<StatusAnswer & { backup_codes?: string[] }> {
    return this.#object("POST", "/api/account/2fa/backup/regenerate", { form: { ...auth } });
  }

  async enableEmail2fa(auth: Reauth): Promise<StatusAnswer> {
    return this.#object("POST", "/api/account/2fa/email/enable", { form: { ...auth } });
  }

  async disableEmail2fa(auth: Reauth): Promise<StatusAnswer> {
    return this.#object("POST", "/api/account/2fa/email/disable", { form: { ...auth } });
  }

  /** Describe the key on your account. The key itself is never returned. */
  async getApiKeyInfo(): Promise<APIKeyInfo> {
    return this.#object("GET", "/api/account/apikey");
  }

  /**
   * Create a new key. **It replaces the current one**, so this client
   * switches to the new key and keeps working. Returns the new key, shown
   * only this once.
   */
  async generateApiKey(auth: Reauth & { expires?: DateInput; readOnly?: boolean }): Promise<string> {
    const { expires, readOnly, ...proof } = auth;
    let exp = expires === undefined ? undefined : dateString(expires);
    if (exp && exp.includes("T")) exp = exp.slice(0, exp.indexOf("T"));
    const d = await this.#object<{ api_key?: string }>("POST", "/api/account/apikey/generate", {
      form: { ...proof, expires: exp, read_only: readOnly ? "1" : undefined },
    });
    const key = d.api_key ?? "";
    if (key) this.#apiKey = key;
    return key;
  }

  /** Delete your key; it stops working at once. If it is this client's key, this is its last call. */
  async revokeApiKey(auth: Reauth): Promise<void> {
    return this.#void("POST", "/api/account/apikey/revoke", { form: { ...auth } });
  }

  // ---------------------------------------------------------------- self-test

  /** Whether the `eyalsec selftest` run with this 32-character hex nonce reached the dashboard. Needs no API key. */
  async getSelftestStatus(nonce: string): Promise<SelftestStatus> {
    const n = nonce.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(n)) throw new TypeError("nonce must be 32 hexadecimal characters");
    return this.#object("GET", `/api/selftest/${n}`, { public: true });
  }
}
