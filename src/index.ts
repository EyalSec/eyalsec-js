/**
 * eyalsec: a typed client for the EyalSec API.
 *
 * ```ts
 * import { EyalSec } from "eyalsec";
 *
 * const client = new EyalSec(); // reads EYALSEC_API_KEY
 * for await (const event of client.iterEvents({ severity: ["critical", "high"] })) {
 *   console.log(event.created_at, event.severity, event.where, event.machine_name);
 * }
 * ```
 *
 * API reference: https://eyalsec.com/docs/api
 */

export { EyalSec, eventFiltersBody, API_KEY_ENV, BASE_URL_ENV, DEFAULT_BASE_URL } from "./client.js";
export type { ClientOptions, FetchLike } from "./client.js";
export {
  EyalSecError,
  ConfigurationError,
  APIConnectionError,
  APITimeoutError,
  APIError,
  BadRequestError,
  AuthenticationError,
  PermissionDeniedError,
  NotFoundError,
  ConflictError,
  UnprocessableEntityError,
  RateLimitError,
  InternalServerError,
  UnexpectedResponseError,
} from "./errors.js";
export type { APIErrorInit } from "./errors.js";
export { eventFromRow, machineFromRow, EVENT_ROW_FIELDS, MACHINE_ROW_FIELDS } from "./rows.js";
export { RuleMode } from "./types.js";
export type * from "./types.js";
export { VERSION } from "./version.js";
