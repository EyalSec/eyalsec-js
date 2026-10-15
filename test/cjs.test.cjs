// The CommonJS entry point loads and exposes the same API as the ES module.
const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

describe("require('eyalsec')", () => {
  it("exports the client, the errors and the helpers", () => {
    const sdk = require("eyalsec");
    assert.equal(typeof sdk.EyalSec, "function");
    assert.equal(typeof sdk.NotFoundError, "function");
    assert.ok(new sdk.NotFoundError(404, "x", { method: "GET", path: "/" }) instanceof sdk.APIError);
    assert.equal(sdk.RuleMode.RAISE, 3);
    assert.equal(typeof sdk.eventFromRow, "function");
    assert.match(sdk.VERSION, /^\d+\.\d+\.\d+/);
  });
});
