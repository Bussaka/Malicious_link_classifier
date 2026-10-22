// Run with: node --test "tests/extension/*.test.mjs"
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

// cache.js is a classic script shared by the content script, popup and service worker,
// so it is evaluated in a sandbox and its globals read back out
const source = readFileSync(new URL("../../ThreatScanner_Extension/cache.js", import.meta.url), "utf8");
// A minimal in-memory chrome.storage.local, enough for lookupVerdict/storeVerdict
const store = {};
const chrome = {
    storage: { local: {
        get(keys, callback) { const out = {}; for (const k of keys) if (k in store) out[k] = store[k]; callback(out); },
        set(items) { Object.assign(store, items); }
    } }
};
const resetStore = () => { for (const k of Object.keys(store)) delete store[k]; };

const sandbox = { Date, URL, chrome };
vm.createContext(sandbox);
vm.runInContext(source + `
    this.exports = { SAFE_TTL_MS, MALICIOUS_TTL_MS, SETTINGS_KEY, PAUSED_INDEFINITELY, safeKey, maliciousKey, allowKey,
                     normalizeUrl, isFresh, isPaused, isScannable, verdictKeys, lookupVerdict, storeVerdict, isVerdictKey };`, sandbox);
const { SAFE_TTL_MS, MALICIOUS_TTL_MS, SETTINGS_KEY, PAUSED_INDEFINITELY, safeKey, maliciousKey, allowKey, normalizeUrl,
        isFresh, isPaused, isScannable, verdictKeys, lookupVerdict, storeVerdict, isVerdictKey } = sandbox.exports;

const lookup = url => new Promise(resolve => lookupVerdict(url, resolve));

test("keys are namespaced so pruning can tell them apart", () => {
    assert.equal(safeKey("example.com"), "safe:example.com");
    assert.equal(maliciousKey("http://evil.xyz/login"), "malicious:http://evil.xyz/login");
    assert.equal(allowKey("example.com"), "allow:example.com");
});

test("normalizeUrl drops the fragment only", () => {
    assert.equal(normalizeUrl("https://a.com/x?y=1#frag"), "https://a.com/x?y=1");
    assert.equal(normalizeUrl("https://a.com/x"), "https://a.com/x");
    assert.equal(normalizeUrl("https://a.com/#/spa/route"), "https://a.com/");
});

test("malicious verdicts expire sooner than safe ones", () => {
    assert.ok(MALICIOUS_TTL_MS < SAFE_TTL_MS);
    assert.equal(SAFE_TTL_MS, 7 * 24 * 3600 * 1000);
    assert.equal(MALICIOUS_TTL_MS, 24 * 3600 * 1000);
});

test("isFresh respects the TTL", () => {
    const now = Date.now();
    assert.equal(isFresh({ timestamp: now - 1000 }, SAFE_TTL_MS), true);
    assert.equal(isFresh({ timestamp: now - SAFE_TTL_MS - 1000 }, SAFE_TTL_MS), false);
    assert.equal(isFresh({ timestamp: now - 2 * 3600 * 1000 }, MALICIOUS_TTL_MS), true);
    assert.equal(isFresh({ timestamp: now - 25 * 3600 * 1000 }, MALICIOUS_TTL_MS), false);
});

test("isFresh rejects missing and pre-1.2 entries", () => {
    assert.equal(isFresh(undefined, SAFE_TTL_MS), false);
    assert.equal(isFresh(null, SAFE_TTL_MS), false);
    // Entries written before expiry existed had a status but no timestamp
    assert.equal(isFresh({ status: "Safe" }, SAFE_TTL_MS), false);
});

test("isPaused handles timed, indefinite and absent pauses", () => {
    assert.equal(isPaused({ pausedUntil: null }), false);
    assert.equal(isPaused({}), false);
    assert.equal(isPaused(undefined), false);
    assert.equal(isPaused({ pausedUntil: Date.now() + 60000 }), true);
    assert.equal(isPaused({ pausedUntil: Date.now() - 1 }), false);   // a timed pause ends by itself
    assert.equal(isPaused({ pausedUntil: PAUSED_INDEFINITELY }), true);
});

test("isScannable accepts only http(s)", () => {
    assert.equal(isScannable("https://example.com/"), true);
    assert.equal(isScannable("HTTP://EXAMPLE.COM"), true);
    for (const url of ["about:blank", "data:text/html,x", "file:///C:/x.html", "chrome://settings", "blob:https://a.com/1", ""]) {
        assert.equal(isScannable(url), false, url);
    }
});

test("verdictKeys: per-domain allow/safe, per-page malicious", () => {
    const keys = verdictKeys("https://shop.example.com/cart?id=1#top");
    assert.equal(keys.allow, "allow:shop.example.com");
    assert.equal(keys.safe, "safe:shop.example.com");
    assert.equal(keys.malicious, "malicious:https://shop.example.com/cart?id=1");
});

test("isVerdictKey spares exceptions and settings", () => {
    assert.equal(isVerdictKey("safe:a.com"), true);
    assert.equal(isVerdictKey("malicious:https://a.com/x"), true);
    assert.equal(isVerdictKey("allow:a.com"), false);
    assert.equal(isVerdictKey(SETTINGS_KEY), false);
});

test("lookupVerdict follows the documented precedence", async () => {
    const url = "https://evil.example/login";
    resetStore();
    assert.equal((await lookup(url)).state, "unknown");

    storeVerdict(url, { status: "Safe" });
    assert.equal((await lookup(url)).state, "safe");
    // Another page on a safelisted domain is safe too
    assert.equal((await lookup("https://evil.example/other")).state, "safe");

    // A blocked page stays blocked even though its domain is safelisted
    storeVerdict(url, { status: "Malicious", confidence: 91.4, explanation: { a: 0.1 }, threshold: 0.686 });
    const blocked = await lookup(url);
    assert.equal(blocked.state, "malicious");
    assert.equal(blocked.entry.confidence, 91.4);
    assert.equal(blocked.entry.threshold, 0.686);
    assert.equal((await lookup("https://evil.example/other")).state, "safe");

    // The user's exception beats the block
    store[allowKey("evil.example")] = true;
    assert.equal((await lookup(url)).state, "allowed");

    // And a pause beats everything
    store[SETTINGS_KEY] = { pausedUntil: PAUSED_INDEFINITELY };
    assert.equal((await lookup(url)).state, "paused");
});

test("lookupVerdict ignores expired verdicts and fills default settings", async () => {
    const url = "https://old.example/page";
    resetStore();
    store[safeKey("old.example")] = { timestamp: Date.now() - SAFE_TTL_MS - 1000 };
    store[maliciousKey(url)] = { confidence: 90, timestamp: Date.now() - MALICIOUS_TTL_MS - 1000 };
    const verdict = await lookup(url);
    assert.equal(verdict.state, "unknown");
    assert.equal(verdict.settings.apiUrl, "http://127.0.0.1:8000");
});
