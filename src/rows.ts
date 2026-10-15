/**
 * The API sends events and machines as arrays, to keep large pages small,
 * and asks clients to read them by position and ignore values they do not
 * know. These functions do that.
 */

import type { Event, Impact, Label, Machine } from "./types.js";

/** Field names of the event row, in API order. */
export const EVENT_ROW_FIELDS = [
  "created_at",
  "where",
  "str_repr",
  "count",
  "machine_name",
  "severity",
  "agent_kind",
  "id",
  "source_label",
  "context",
  "suppressed",
  "sanitize_reason",
  "impact",
  "labels",
  "has_comment",
  "extension",
  "taint_source",
] as const;

/** Field names of the machine row, in API order. */
export const MACHINE_ROW_FIELDS = [
  "created_at",
  "machine_name",
  "status",
  "public_id",
  "os_type",
  "installed_build",
  "current_build",
  "python_version",
  "socket_only",
  "clone_locked",
  "stalled",
  "stale_agent",
  "agent_kind",
] as const;

function str(v: unknown): string {
  return v === null || v === undefined ? "" : String(v);
}

function num(v: unknown): number {
  if (typeof v === "number") return Number.isFinite(v) ? v : 0;
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }
  if (typeof v === "boolean") return v ? 1 : 0;
  return 0;
}

function bool(v: unknown): boolean {
  if (typeof v === "string") return v.trim().toLowerCase() === "true";
  return Boolean(v);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function impacts(v: unknown): Impact[] {
  if (!Array.isArray(v)) return [];
  return v.filter(isRecord).map((d) => ({ label: str(d.label), sev: str(d.sev) }));
}

function labels(v: unknown): Label[] {
  if (!Array.isArray(v)) return [];
  return v.filter(isRecord).map((d) => ({ id: num(d.id), name: str(d.name), color: str(d.color) }));
}

/** Read one event row (an array, as the API sends it) into an {@link Event}. */
export function eventFromRow(row: unknown): Event {
  // Tolerate an object form, should one ever arrive.
  const r: unknown[] = Array.isArray(row)
    ? row
    : isRecord(row)
      ? EVENT_ROW_FIELDS.map((f) => row[f])
      : [];
  return {
    created_at: str(r[0]),
    where: str(r[1]),
    str_repr: str(r[2]),
    count: num(r[3]),
    machine_name: str(r[4]),
    severity: str(r[5]),
    agent_kind: str(r[6]),
    id: num(r[7]),
    source_label: str(r[8]),
    context: str(r[9]),
    suppressed: bool(r[10]),
    sanitize_reason: str(r[11]),
    impact: impacts(r[12]),
    labels: labels(r[13]),
    has_comment: bool(r[14]),
    extension: str(r[15]),
    taint_source: str(r[16]),
    extra: Array.isArray(row) ? row.slice(EVENT_ROW_FIELDS.length) : [],
    raw: Array.isArray(row) ? row : r,
  };
}

/** Read one machine row (an array, as the API sends it) into a {@link Machine}. */
export function machineFromRow(row: unknown): Machine {
  const r: unknown[] = Array.isArray(row)
    ? row
    : isRecord(row)
      ? MACHINE_ROW_FIELDS.map((f) => row[f])
      : [];
  return {
    created_at: str(r[0]),
    machine_name: str(r[1]),
    status: str(r[2]),
    public_id: str(r[3]),
    os_type: str(r[4]),
    installed_build: str(r[5]),
    current_build: str(r[6]),
    python_version: str(r[7]),
    socket_only: bool(r[8]),
    clone_locked: bool(r[9]),
    stalled: bool(r[10]),
    stale_agent: bool(r[11]),
    agent_kind: str(r[12]),
    extra: Array.isArray(row) ? row.slice(MACHINE_ROW_FIELDS.length) : [],
    raw: Array.isArray(row) ? row : r,
  };
}
