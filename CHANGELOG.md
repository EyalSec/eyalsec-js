# Changelog

## 0.1.0

First release.

- A typed method for every endpoint in the [EyalSec API reference](https://eyalsec.com/docs/api): events, runs, counts, export and map; machines and their install commands; the CI install and findings check; filters, rules, taint sources, web protection, unique events and outbound connections; rule templates; labels and notes; the activity log and account settings.
- `iterEvents`, `iterRuns` and `iterActivity` follow the paging for you, including past empty event pages.
- Event and machine rows are read by position into typed objects, keeping the original row and any newer values.
- Errors are classes you can catch by meaning (`NotFoundError`, `RateLimitError`, ...).
- Rate-limited requests are retried after `Retry-After`; reads are retried after a dropped connection or a 502, 503 or 504.
- ES module and CommonJS builds with type definitions. No runtime dependencies. Node.js 18 or newer.
