/**
 * Errors the client throws.
 *
 * Every error is an {@link EyalSecError}. An answer with an error status
 * becomes an {@link APIError} subclass chosen by the status, so you can catch
 * by meaning (`instanceof NotFoundError`) or read `err.status`.
 */

/** Base class for every error this library throws on purpose. */
export class EyalSecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** The client was set up in a way that cannot work, such as having no API key. */
export class ConfigurationError extends EyalSecError {}

/** The request got no answer: DNS, TLS, a refused or dropped connection. */
export class APIConnectionError extends EyalSecError {
  /** @param cause The underlying error from `fetch`, kept as `err.cause`. */
  constructor(message: string, cause?: unknown) {
    super(message);
    if (cause !== undefined) {
      Object.defineProperty(this, "cause", { value: cause, enumerable: false, writable: true, configurable: true });
    }
  }
}

/** The request took longer than the client's `timeout`. */
export class APITimeoutError extends APIConnectionError {}

export interface APIErrorInit {
  method: string;
  path: string;
  body?: unknown;
  retryAfter?: number | undefined;
}

/** The API answered with an error status. */
export class APIError extends EyalSecError {
  /** The HTTP status, such as 403. */
  readonly status: number;
  /** The server's message, from `{"error": "..."}` or a plain-text body. Empty when it sent none. */
  readonly serverMessage: string;
  /** The HTTP method of the request that failed. */
  readonly method: string;
  /** The path of the request that failed, such as `/api/event/42`. */
  readonly path: string;
  /** The parsed JSON body of the answer, when it was JSON. */
  readonly body: unknown;
  /** Seconds the server asked us to wait (`Retry-After`), when it said. */
  readonly retryAfter: number | undefined;

  constructor(status: number, serverMessage: string, init: APIErrorInit) {
    const what = serverMessage ? `: ${serverMessage}` : "";
    super(`${init.method} ${init.path} answered ${status}${what}`);
    this.status = status;
    this.serverMessage = serverMessage;
    this.method = init.method;
    this.path = init.path;
    this.body = init.body;
    this.retryAfter = init.retryAfter;
  }
}

/** 400: malformed JSON, an invalid regex, an unreadable cursor or date, or an unknown value. */
export class BadRequestError extends APIError {}

/** 401: the API key is missing, wrong, revoked or expired. */
export class AuthenticationError extends APIError {}

/**
 * 403: not allowed. For example a read-only key trying to write, a product or
 * feature your account does not have, a wrong password on an account call, or
 * a write on an account limited to reading.
 */
export class PermissionDeniedError extends APIError {}

/**
 * 404: not found. The API also answers 404 for things that belong to another
 * account, so their existence is never confirmed.
 */
export class NotFoundError extends APIError {}

/** 409: a conflict with the current state, such as a full machine limit or a label name in use. */
export class ConflictError extends APIError {}

/** 422: a field is missing or invalid. */
export class UnprocessableEntityError extends APIError {}

/** 429: a rate limit was hit, or the account is locked after wrong passwords. See `retryAfter`. */
export class RateLimitError extends APIError {}

/** 5xx: something failed on the EyalSec side. Try again; contact support@eyalsec.com if it persists. */
export class InternalServerError extends APIError {}

/** The answer was not what the API documents: a redirect, or a body that is not JSON. */
export class UnexpectedResponseError extends APIError {}

/** The {@link APIError} subclass for a status. */
export function errorClassFor(status: number): typeof APIError {
  switch (status) {
    case 400:
      return BadRequestError;
    case 401:
      return AuthenticationError;
    case 403:
      return PermissionDeniedError;
    case 404:
      return NotFoundError;
    case 409:
      return ConflictError;
    case 422:
      return UnprocessableEntityError;
    case 429:
      return RateLimitError;
    default:
      return status >= 500 ? InternalServerError : APIError;
  }
}
