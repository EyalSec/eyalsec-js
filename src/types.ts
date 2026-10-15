/**
 * Types for what the EyalSec API takes and returns.
 *
 * Field names are the API's own, exactly as the API reference
 * (https://eyalsec.com/docs/api) spells them, so a page of the reference reads
 * straight across to these types. Records carry an index signature where the
 * API may add fields later, so a newer server never breaks an older client.
 */

/** A string union that still accepts values a newer server may send. */
type Open<T extends string> = T | (string & {});

export type Severity = Open<"critical" | "high" | "medium" | "low" | "info">;

/** Which product's events: `python` (es-python) or `browser` (es-chromium). */
export type View = Open<"python" | "browser">;

/** `live` (not suppressed, the default), `suppressed`, or `all`. */
export type Bucket = Open<"live" | "suppressed" | "all">;

/** Taint source categories, as the events query's `sources` filter takes them. */
export type SourceCategory = Open<"socket" | "file" | "stdin" | "env" | "argv" | "manual" | "fuzzer" | "foreign">;

export type ScopeMode = Open<"is" | "ends" | "regex">;

/** The events page's scope bar. */
export interface Scope {
  mode: ScopeMode;
  value: string;
  include_empty?: boolean;
}

export interface Condition {
  field: string;
  op: string;
  value: string;
  negate?: boolean;
}

/** The events page's condition builder. */
export interface Advanced {
  match?: "all" | "any";
  conditions: Condition[];
}

/** A date for a filter: a `Date`, or a string as `YYYY-MM-DD` or RFC 3339. */
export type DateInput = Date | string;

/**
 * Filters shared by the events query, the export and the map. Every field is
 * optional and matches a control on the events page.
 */
export interface EventFilters {
  /** Omit for every product on your account. */
  view?: View;
  bucket?: Bucket;
  /** `newest` (the default) or `severity` (most severe first). */
  sort?: "newest" | "severity";
  from?: DateInput;
  /** Includes the whole of that day. */
  to?: DateInput;
  /** One machine, by display name (exact match). */
  machine?: string;
  severity?: Severity | Severity[];
  sources?: SourceCategory | SourceCategory[];
  /** Impact classes, such as `xss` or `sqli`. */
  tags?: string | string[];
  /** Your label ids. */
  labels?: number[];
  /** A case-insensitive regex: keep events whose sink label (`where`) matches. */
  whitelist_repr?: string;
  /** A case-insensitive regex: drop events whose sink label (`where`) matches. */
  blacklist_repr?: string;
  /** Only es-chromium events whose sink can run script. Needs `view: "browser"`. */
  xss_only?: boolean;
  scope?: Scope;
  advanced?: Advanced;
  /** Shortcut: keep only what one run produced (a `run_uid`). Adds a `run` condition to `advanced`. */
  run?: string;
  /** Merged into the request body as is, for fields this version does not know. */
  extra?: Record<string, unknown>;
}

export interface Impact {
  label: string;
  sev: Severity;
}

export interface Label {
  id: number;
  name: string;
  color: string;
}

/**
 * One event from the events list. The API sends it as an array; the client
 * reads it by position into these names (the "event row" table in the API
 * reference).
 */
export interface Event {
  /** When the event was first seen (RFC 3339). */
  created_at: string;
  /** The sink label: what happened, where. */
  where: string;
  /** The value that reached the sink, as text. */
  str_repr: string;
  /** How many times it happened. */
  count: number;
  machine_name: string;
  severity: Severity;
  /** The product that reported it, such as `python`. */
  agent_kind: string;
  /** The event id, for {@link EyalSec.getEvent}, labels and notes. */
  id: number;
  source_label: string;
  /** The page (es-chromium) or the file written to (an es-python write). */
  context: string;
  /** `true` when the sanitizer decided the value cannot reach its sink dangerously. */
  suppressed: boolean;
  sanitize_reason: string;
  /** Up to three impact classes, worst first. */
  impact: Impact[];
  labels: Label[];
  has_comment: boolean;
  /** The browser extension an es-chromium event came from. */
  extension: string;
  /** The es-python taint source, by the name a rule's `source` takes. */
  taint_source: string;
  /** Values past the ones this version knows, in order. */
  extra: unknown[];
  /** The row exactly as the API sent it. */
  raw: unknown[];
}

export interface HiddenBy {
  id: number;
  label: string;
}

export interface EventPage {
  events: Event[];
  /** Pass back as `cursor` for the next page. Empty when you have everything. */
  next_cursor: string;
  scanned: number;
  exhausted: boolean;
  oldest_examined: string;
  /** Your quota, per product. `-1` means none. */
  event_limit: number;
  event_limit_monthly: boolean;
  /** Set when one of your Hide rules matches every event. */
  hidden_by?: HiddenBy;
  [key: string]: unknown;
}

export interface EventRun {
  run_uid: string;
  cmdline: string;
  env: string;
  count: number;
  first_seen: string;
  last_seen: string;
  [key: string]: unknown;
}

export interface EventExtension {
  id: string;
  name: string;
  version: string;
  label: string;
}

/** The large fields of one event, from {@link EyalSec.getEvent}. */
export interface EventDetail {
  trace: string;
  origin: string;
  repr_created: string;
  detail: string;
  rule_source?: string;
  source_code: string;
  sink_code: string;
  comment: string;
  extension: EventExtension;
  runs: EventRun[];
  source: string;
  [key: string]: unknown;
}

export interface Run {
  run_uid: string;
  cmdline: string;
  first_seen: string;
  last_seen: string;
  events: number;
  occurrences: number;
  [key: string]: unknown;
}

export interface RunPage {
  runs: Run[];
  next_before: string;
  [key: string]: unknown;
}

export interface ListRunsOptions {
  /** One machine, by display name. */
  machine?: string;
  /** A case-insensitive piece of the command line. */
  q?: string;
  /** The `next_before` of the previous page. */
  before?: string;
  /** Rows per page, 1 to 200. */
  limit?: number;
}

export interface EventStats {
  total_hits: number;
  unique_types: number;
  last_1h: number;
  last_24h: number;
  last_7d: number;
  top_events: { where: string; count: number }[];
  recent: { time: string; where: string; count: number }[];
  timeline_14d: { date: string; count: number }[];
  first_detection?: string;
  latest_detection?: string;
  [key: string]: unknown;
}

export interface EventCount {
  count: number;
  view: string;
  event_limit: number;
  event_limit_monthly: boolean;
  [key: string]: unknown;
}

export interface ViewCountsOptions {
  bucket?: Bucket;
  scope?: string;
  /** Required with `scope`. */
  scope_mode?: ScopeMode;
  scope_empty?: boolean;
}

export interface VisibilityCounts {
  live: number;
  suppressed: number;
  [key: string]: number;
}

export interface MapEntry {
  events: number;
  hits: number;
  severity: Severity;
}

export interface EventMap {
  events: number;
  hits: number;
  truncated: boolean;
  max_events: number;
  sources: (MapEntry & { kind: string })[];
  files: (MapEntry & { path: string })[];
  sinks: (MapEntry & { sink: string })[];
  links: (MapEntry & { source: string; file: string; sink: string })[];
  /** Present when you asked for a focus. Its rows are read into {@link Event}s. */
  focus?: { events: Event[]; truncated: boolean };
  [key: string]: unknown;
}

export interface EventMapOptions extends Omit<EventFilters, "view" | "sort" | "xss_only"> {
  /** Focus on one source: `socket`, `file`, ..., or `other`. */
  source?: string;
  /** Focus on one file path, exactly as in `files`. An empty string selects the file with no known path. */
  file?: string;
  /** Focus on one sink, exactly as in `sinks`. */
  sink?: string;
  /** `focus` returns only the `focus` object. */
  only?: "focus";
}

export type ExportFormat = "csv" | "json";

export interface SavedSearch {
  id: number;
  name: string;
  view: string;
  query: string;
  [key: string]: unknown;
}

/** A machine from the machines list (the "machine row" table in the API reference). */
export interface Machine {
  created_at: string;
  machine_name: string;
  /** `created`, `pending`, `installed` or `failed`. */
  status: Open<"created" | "pending" | "installed" | "failed">;
  /** The machine's handle in every other call. */
  public_id: string;
  /** Such as `ubuntu_24_04_x86_64`, or `auto` until an es-python install decides it. */
  os_type: string;
  installed_build: string;
  current_build: string;
  python_version: string;
  /** Retired; machines added now always read `false`. */
  socket_only: boolean;
  clone_locked: boolean;
  stalled: boolean;
  stale_agent: boolean;
  agent_kind: string;
  extra: unknown[];
  raw: unknown[];
}

export interface AddMachineOptions {
  /** `python` (the default) or `browser`. */
  product?: "python" | "browser";
  /** With `arch`, picks the build. Leave both out to have it detected at install. */
  distro?: string;
  arch?: string;
  /** Such as `3.13`, or `auto`. */
  python_version?: string;
}

/** The answer to {@link EyalSec.addMachine}. Its keys are capitalized, as the API sends them. */
export interface NewMachine {
  Name: string;
  OsType: string;
  Status: string;
  PublicID: string;
  PythonVersion?: string;
  SocketOnly?: string;
  AgentKind: string;
  [key: string]: unknown;
}

export interface InstallCommand {
  /** Single use; expires quickly. */
  secret: string;
  script_path: string;
  os_type?: string;
  expires_in?: number;
  [key: string]: unknown;
}

export interface Distro {
  id: string;
  label: string;
  archs: string[];
  [key: string]: unknown;
}

export interface PythonVersions {
  versions: string[];
  default: string;
  [key: string]: unknown;
}

export interface CIInstallOptions {
  /** Required the first time, when the machine does not exist yet. */
  distro?: string;
  arch?: string;
  python_version?: string;
}

export interface CIInstall {
  machine_name: string;
  public_id: string;
  created: boolean;
  os_type: string;
  python_version: string;
  secret: string;
  script_path: string;
  expires_in: number;
  /** The server's clock when the secret was made; pass it as `since` to {@link EyalSec.ciFindings}. */
  server_time: string;
  events_url: string;
  [key: string]: unknown;
}

export interface CIFindingsOptions {
  /** `high` on the server when omitted. */
  min_severity?: Severity;
  /** How many findings to list, 0 to 100 (default 20). */
  limit?: number;
}

export interface CIFinding {
  id: number;
  severity: Severity;
  where: string;
  count: number;
  last_seen: string;
  new: boolean;
  [key: string]: unknown;
}

export interface CIFindings {
  machine: string;
  since: string;
  min_severity: Severity;
  /** Events at or above `min_severity` that a run reached in the window. */
  findings: number;
  /** Of `findings`, the ones no earlier run had reached. */
  new_findings: number;
  total: number;
  by_severity: Record<string, number>;
  truncated: boolean;
  hidden_by: string;
  url: string;
  events: CIFinding[];
  [key: string]: unknown;
}

export type FilterMode = Open<"blacklist" | "whitelist">;
export type FilterTarget = Open<"where" | "origin" | "tag">;

export interface Filter {
  id: number;
  pattern: string;
  label: string;
  mode: FilterMode;
  target: FilterTarget;
  enabled: boolean;
  engine?: string;
  [key: string]: unknown;
}

export interface CreateFilterOptions {
  target?: FilterTarget;
  /** `any` (the default) or one product's view value. */
  engine?: string;
  label?: string;
  enabled?: boolean;
}

export interface UpdateFilterOptions {
  pattern?: string;
  mode?: FilterMode;
  target?: FilterTarget;
  label?: string;
  enabled?: boolean;
}

/** What a rule does. */
export const RuleMode = {
  HIDE: 1,
  SHOW: 2,
  RAISE: 3,
  DONT_SEND: 4,
} as const;
export type RuleMode = (typeof RuleMode)[keyof typeof RuleMode];

/** A machine rule. Its keys are capitalized as the API sends them, all but `sanitize_scope` and `match_on`. */
export interface Rule {
  ID: number;
  Source: string;
  EventPattern: string;
  Mode: number;
  Action: string;
  Polarity: string;
  Label: string;
  Enabled: boolean;
  sanitize_scope: string;
  match_on: string[];
  [key: string]: unknown;
}

export interface CreateRuleOptions {
  /** A `public_id`; omit (or `""`) for your global rules. */
  machine?: string;
  /** A regex on the sink label. Empty means all events. */
  event_pattern?: string;
  /** 1 Hide, 2 Show (the default), 3 Raise, 4 Don't send. See {@link RuleMode}. */
  mode?: RuleMode | number;
  /** `any` (the default), a source name such as `socket` or `weak-random`, or a number. */
  source?: string;
  /** `any`, `unsanitized`, `sanitized`, `conditional` or `sanitized:<class>`. */
  sanitize_scope?: string;
  label?: string;
  enabled?: boolean;
  /** Make the rule from this event id. */
  from_event?: number;
  /** With `from_event`: any of `source`, `trace`, `detail`, `origin`. */
  match_on?: string[];
  /** With `from_event`: scope the rule to the machine that sent the event. */
  event_machine?: boolean;
}

export interface UpdateRuleOptions {
  event_pattern?: string;
  mode?: RuleMode | number;
  source?: string;
  sanitize_scope?: string;
  label?: string;
  enabled?: boolean;
}

export type TaintState = Open<"on" | "off" | "unset">;

export interface WebProtection {
  settings: Record<string, string>;
  inherited: Record<string, string>;
  can_block: boolean;
  [key: string]: unknown;
}

export interface BlockedClient {
  id: number;
  address: string;
  source: string;
  reason: string;
  created_at: string;
  expires_at: string | null;
  [key: string]: unknown;
}

export interface BlockClientOptions {
  reason?: string;
  /** Hours until it expires; 0 or omitted for never. */
  hours?: number;
}

export interface RouteStats {
  machine: string;
  method: string;
  route: string;
  hits: number;
  s2xx: number;
  s3xx: number;
  s4xx: number;
  s5xx: number;
  events: number;
  last_seen: string;
  [key: string]: unknown;
}

export type UniquenessAxis = Open<"source" | "detail" | "trace" | "machine" | "origin">;

export interface EventUniqueness {
  agent_kind: string;
  machine: string;
  axes: UniquenessAxis[];
  inherited: boolean;
  available: UniquenessAxis[];
  baseline: string[];
  [key: string]: unknown;
}

export interface EgressRule {
  action: Open<"allow" | "deny">;
  target: string;
  note?: string;
}

export interface EgressPolicy {
  mode: string | null;
  default: string | null;
  on_violation: string | null;
  rules: EgressRule[];
  [key: string]: unknown;
}

export interface Egress {
  machine?: string;
  scope: EgressPolicy;
  account?: EgressPolicy;
  effective: EgressPolicy;
  defaults: { mode: string; default: string; on_violation: string };
  max_rules: number;
  keywords: string[];
  [key: string]: unknown;
}

export interface SetEgressOptions {
  /** A `public_id`; omit for your account. */
  machine?: string;
  /** `untrusted` or `all`; `null` or omitted inherits. */
  mode?: "untrusted" | "all" | null;
  default?: "allow" | "deny" | null;
  on_violation?: "block" | "report" | null;
}

export interface TemplateItem {
  source: string;
  event_pattern: string;
  mode: RuleMode | number;
  sanitize_scope?: string;
  position?: number;
}

export interface RuleTemplate {
  id: number;
  /** `me` for your own, `eyalsec` for the published ones. */
  owner: Open<"me" | "eyalsec">;
  name: string;
  description: string;
  items: TemplateItem[];
  product?: string;
  category?: string;
  [key: string]: unknown;
}

export interface TemplateCategory {
  key: string;
  name: string;
  blurb: string;
  [key: string]: unknown;
}

export interface RuleTemplateList {
  templates: RuleTemplate[];
  categories: TemplateCategory[];
  [key: string]: unknown;
}

export interface TemplateApplyResult {
  added: number;
  skipped_raise: number;
  skipped_duplicate: number;
  [key: string]: unknown;
}

export type LabelColor = Open<"amber" | "cyan" | "red" | "green" | "blue" | "slate" | "violet" | "pink">;

export interface ActivityEntry {
  time: string;
  id: number;
  action: string;
  description: string;
  target: string;
  source_ip: string;
  /** `session` or `apikey`. */
  auth_method: string;
  outcome: string;
  [key: string]: unknown;
}

export interface ActivityOptions {
  /** One exact action name, such as `machine.create`. */
  action?: string;
  outcome?: "success" | "failure";
  before_ts?: string;
  before_id?: number;
}

export interface ActivityPage {
  entries: ActivityEntry[];
  [key: string]: unknown;
}

export interface Account {
  username: string;
  email: string;
  timezone: string;
  email_verified: boolean;
  totp_enabled: boolean;
  email_2fa_enabled: boolean;
  /** Per product. */
  machine_limit: number;
  /** Per product's list; `-1` means none. */
  event_limit: number;
  event_limit_monthly: boolean;
  /** Whether Raise rules are enabled for you. */
  grant_raise: boolean;
  [key: string]: unknown;
}

export interface OnboardingState {
  has_plan: boolean;
  has_python: boolean;
  machines_total: number;
  machines_installed: number;
  machines_pending: number;
  sources_on: boolean;
  ran: boolean;
  events_total: number;
  selftest_seen: boolean;
  next_step: Open<"plan" | "add_machine" | "install" | "sources" | "run" | "first_event" | "done">;
  empty_reason: string;
  [key: string]: unknown;
}

export interface APIKeyInfo {
  exists: boolean;
  key_prefix?: string;
  /** `full` or `read_only`. */
  scope?: string;
  created_at?: string;
  expires_at?: string;
  last_used_at?: string;
  last_ip?: string;
  [key: string]: unknown;
}

/** Proof that account calls ask for: your password, plus a two-factor code when it is on. */
export interface Reauth {
  password: string;
  /** An authenticator or backup code, when two-factor sign-in is on. */
  totp?: string;
}

export interface StatusAnswer {
  status: string;
  note?: string;
  [key: string]: unknown;
}

export interface SelftestStatus {
  received: boolean;
  dashboard_url?: string;
  [key: string]: unknown;
}
