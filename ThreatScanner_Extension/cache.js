// Shared storage layout and verdict logic, used by content.js, popup.js, options.js and background.js
// chrome.storage.local:
//   safe:<hostname>   -> { timestamp }                                       whole domain trusted for SAFE_TTL_MS
//   malicious:<url>   -> { confidence, explanation, threshold, timestamp }   that exact page blocked for MALICIOUS_TTL_MS
//   allow:<hostname>  -> true                                                user chose to proceed; never expires
//   settings          -> { apiUrl, pausedUntil }                             see DEFAULT_SETTINGS
// chrome.storage.session (in memory):
//   apiStatus         -> { online, checkedAt, model, threshold, error }      written by background.js
const SAFE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MALICIOUS_TTL_MS = 24 * 60 * 60 * 1000;

const SETTINGS_KEY = "settings";
const DEFAULT_SETTINGS = {
    apiUrl: "http://127.0.0.1:8000",
    // null = protection on; a timestamp = paused until then; PAUSED_INDEFINITELY = until resumed
    pausedUntil: null
};
const PAUSED_INDEFINITELY = -1;

function safeKey(hostname) { return "safe:" + hostname; }
function maliciousKey(url) { return "malicious:" + url; }
function allowKey(hostname) { return "allow:" + hostname; }

// Fragments never reach the server, so they shouldn't create separate cache entries
function normalizeUrl(url) { return url.split("#")[0]; }

function isFresh(entry, ttlMs) {
    return Boolean(entry && entry.timestamp && Date.now() - entry.timestamp < ttlMs);
}

function isPaused(settings) {
    if (!settings || settings.pausedUntil === null || settings.pausedUntil === undefined) return false;
    return settings.pausedUntil === PAUSED_INDEFINITELY || Date.now() < settings.pausedUntil;
}

function isScannable(url) {
    return /^https?:\/\//i.test(url);
}

function verdictKeys(url) {
    const hostname = new URL(url).hostname;
    return { allow: allowKey(hostname), malicious: maliciousKey(normalizeUrl(url)), safe: safeKey(hostname) };
}

// Resolves what is already known about a URL. state is one of:
//   paused | allowed | malicious | safe | unknown   (unknown = needs a scan)
// The order matters: a blocked page stays blocked even after another page on its domain scans Safe.
function lookupVerdict(url, callback) {
    const keys = verdictKeys(url);
    chrome.storage.local.get([keys.allow, keys.malicious, keys.safe, SETTINGS_KEY], result => {
        const settings = Object.assign({}, DEFAULT_SETTINGS, result[SETTINGS_KEY]);
        if (isPaused(settings)) return callback({ state: "paused", settings });
        if (result[keys.allow]) return callback({ state: "allowed", settings });
        if (isFresh(result[keys.malicious], MALICIOUS_TTL_MS)) {
            return callback({ state: "malicious", entry: result[keys.malicious], settings });
        }
        if (isFresh(result[keys.safe], SAFE_TTL_MS)) return callback({ state: "safe", entry: result[keys.safe], settings });
        callback({ state: "unknown", settings });
    });
}

// Safe verdicts trust the whole domain; Malicious ones only block that page,
// so one bad URL doesn't condemn every other page on the site
function storeVerdict(url, data) {
    const keys = verdictKeys(url);
    const entry = {};
    if (data.status === "Malicious") {
        entry[keys.malicious] = {
            confidence: data.confidence,
            explanation: data.explanation,
            threshold: data.threshold,
            timestamp: Date.now()
        };
    } else {
        entry[keys.safe] = { timestamp: Date.now() };
    }
    chrome.storage.local.set(entry);
}

function isVerdictKey(key) {
    return key.startsWith("safe:") || key.startsWith("malicious:");
}
