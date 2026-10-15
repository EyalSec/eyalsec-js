# Security

Please report a security problem in this client, or in EyalSec itself, to **security@eyalsec.com** rather than in a public issue. We will reply to confirm we have it and keep you updated until it is fixed. The EyalSec security page is at <https://eyalsec.com/security>.

This library sends your API key only to the address you configure, only over HTTPS (plain HTTP is accepted for `localhost` alone), and never includes it in an error message or in what `console.log` or `JSON.stringify` show of the client.

Releases are published to npm from this repository's GitHub Actions with [npm provenance](https://docs.npmjs.com/generating-provenance-statements), so you can check that a version was built from a commit here: `npm audit signatures`.
