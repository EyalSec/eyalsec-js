/**
 * Optional checks against a real EyalSec account.
 *
 *   EYALSEC_LIVE=1 EYALSEC_API_KEY=es2_... npm run test:live
 *
 * runs a read-only pass. Add EYALSEC_LIVE_WRITES=1 (and a full-access key) to
 * also create, change and delete a label, a filter, a rule, a saved search,
 * a rule template and two machines (one through the CI install), cleaning
 * each one up again. Point EYALSEC_URL at a
 * test account, not one you depend on.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";

import { ConflictError, EyalSec, NotFoundError, RuleMode } from "eyalsec";

const live = process.env.EYALSEC_LIVE === "1";
const writes = live && process.env.EYALSEC_LIVE_WRITES === "1";

describe("live", { skip: !live && "set EYALSEC_LIVE=1 to run" }, () => {
  const client = new EyalSec();

  it("reads everything a read-only key may read", async () => {
    const account = await client.getAccount();
    assert.ok(account.username);
    assert.equal((await client.getApiKeyInfo()).exists, true);

    const machines = await client.listMachines();
    assert.ok(machines.every((m) => m.public_id));

    const page = await client.queryEvents();
    assert.ok(Array.isArray(page.events));
    const events = [];
    for await (const e of client.iterEvents({ maxPages: 5 })) events.push(e);
    if (events[0]) {
      const detail = await client.getEvent(events[0].id);
      assert.equal(typeof detail.trace, "string");
      assert.ok(Array.isArray(detail.runs));
    }
    assert.ok(Array.isArray((await client.queryEvents({ sort: "severity" })).events));

    for await (const _ of client.iterRuns({ maxPages: 2 })) break;
    await client.getEventStats();
    await client.getEventCount("python");
    assert.ok("python" in (await client.getEventViewCounts()));
    const vis = await client.getEventVisibilityCounts();
    assert.equal(typeof vis.live, "number");
    await client.listEventNames();
    await client.listSavedSearches();
    await client.listFilters();
    await client.listRules();
    assert.ok(Object.keys(await client.getTaint()).length > 0);
    assert.ok((await client.getEventUniqueness("python")).available.length > 0);
    assert.ok(Array.isArray((await client.listRuleTemplates()).templates));
    await client.listLabels();
    assert.ok((await client.getOnboardingState()).next_step);
    assert.ok(Array.isArray((await client.listActivity()).entries));
    assert.ok((await client.listSupportedOsTypes()).length > 0);
    assert.ok((await client.listSupportedPythonVersions()).default);
    assert.match((await client.exportEvents("json", { from: "2026-01-01" })).trimStart(), /^[[{]/);
    assert.equal(typeof (await client.getEventMap()).events, "number");
    await client.getWebProtection();
    await client.getEgress();
    await assert.rejects(client.getEvent(2 ** 52), NotFoundError);
  });

  it("creates, changes and removes what it made", { skip: !writes && "set EYALSEC_LIVE_WRITES=1 to run" }, async () => {
    const tag = `sdk-js-${randomBytes(4).toString("hex")}`;

    const label = await client.createLabel(tag, "cyan");
    try {
      await assert.rejects(client.createLabel(tag), ConflictError);
      await client.updateLabel(label.id, `${tag}-x`, "green");
      assert.ok((await client.listLabels()).some((l) => l.name === `${tag}-x` && l.color === "green"));
      const [event] = (await client.queryEvents()).events;
      if (event) {
        await client.attachLabel(event.id, label.id);
        await client.setNote(event.id, `${tag} note`);
        assert.equal((await client.getEvent(event.id)).comment, `${tag} note`);
        await client.deleteNote(event.id);
        await client.detachLabel(event.id, label.id);
      }
    } finally {
      await client.deleteLabel(label.id);
    }

    const filter = await client.createFilter(`^${tag}$`, "blacklist", { label: tag });
    try {
      assert.equal((await client.updateFilter(filter.id, { enabled: false })).enabled, false);
    } finally {
      await client.deleteFilter(filter.id);
    }

    const rule = await client.createRule({ event_pattern: `^${tag}$`, mode: RuleMode.HIDE, label: tag });
    try {
      assert.equal((await client.updateRule(rule.ID, { enabled: false })).Enabled, false);
    } finally {
      await client.deleteRule(rule.ID);
    }

    const searches = await client.saveSearch(tag, "view=python&sev=critical");
    const saved = searches.find((s) => s.name === tag);
    assert.ok(saved);
    await client.deleteSavedSearch(saved.id);

    const tpl = await client.createRuleTemplate(tag, [{ source: "any", event_pattern: `^${tag}$`, mode: RuleMode.SHOW }]);
    try {
      await client.updateRuleTemplate(tpl.id, tag, [{ source: "socket", event_pattern: `^${tag}$`, mode: RuleMode.SHOW }]);
      assert.ok((await client.listRuleTemplates()).templates.some((t) => t.id === tpl.id && t.items[0]?.source === "socket"));
    } finally {
      await client.deleteRuleTemplate(tpl.id);
    }

    const added = await client.addMachine(tag);
    try {
      assert.equal(added.Status, "created");
      assert.equal((await client.renameMachine(added.PublicID, `${tag}-r`)).machine_name, `${tag}-r`);
      const cmd = await client.getInstallCommand(added.PublicID, { attested: true });
      assert.ok(cmd.secret && cmd.script_path);
    } finally {
      await client.deleteMachine(added.PublicID);
    }

    const ci = await client.ciInstall(`${tag}-ci`, { attested: true, distro: "ubuntu_24_04", arch: "x86_64" });
    try {
      assert.equal(ci.created, true);
      const findings = await client.ciFindings(ci.machine_name, ci.server_time, { min_severity: "high" });
      assert.equal(findings.total, 0);
      assert.equal(findings.findings, 0);
    } finally {
      await client.deleteMachine(ci.public_id);
    }
  });
});
