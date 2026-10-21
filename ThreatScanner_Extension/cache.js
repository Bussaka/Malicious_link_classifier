// Shared cache layout for chrome.storage.local, used by content.js, popup.js and background.js
//   safe:<hostname>   -> { timestamp }                            whole domain trusted for SAFE_TTL_MS
//   malicious:<url>   -> { confidence, explanation, threshold, timestamp }   that exact page blocked for MALICIOUS_TTL_MS
//   allow:<hostname>  -> true                                     user chose to proceed; never expires
const SAFE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MALICIOUS_TTL_MS = 24 * 60 * 60 * 1000;

function safeKey(hostname) { return "safe:" + hostname; }
function maliciousKey(url) { return "malicious:" + url; }
function allowKey(hostname) { return "allow:" + hostname; }

// Fragments never reach the server, so they shouldn't create separate cache entries
function normalizeUrl(url) { return url.split("#")[0]; }

function isFresh(entry, ttlMs) {
    return Boolean(entry && entry.timestamp && Date.now() - entry.timestamp < ttlMs);
}
