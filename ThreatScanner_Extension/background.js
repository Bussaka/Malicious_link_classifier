importScripts("cache.js");

// The page stays hidden while a scan runs, so a hung API must not hold it hostage
const SCAN_TIMEOUT_MS = 5000;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scanUrl") {
        fetch("http://127.0.0.1:8000/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url }),
            signal: AbortSignal.timeout(SCAN_TIMEOUT_MS)
        })
        .then(response => {
            if (!response.ok) throw new Error("API returned HTTP " + response.status);
            return response.json();
        })
        .then(data => sendResponse({ success: true, data: data }))
        .catch(err => sendResponse({ success: false, error: err.toString() }));

        // Returning true tells Chrome we will send the response asynchronously
        return true;
    }
});

// Drops expired verdicts and pre-1.2 entries (keyed by bare hostname, no expiry)
function pruneCache() {
    chrome.storage.local.get(null, function(items) {
        const stale = Object.keys(items).filter(key => {
            if (key.startsWith("allow:")) return false;
            if (key.startsWith("safe:")) return !isFresh(items[key], SAFE_TTL_MS);
            if (key.startsWith("malicious:")) return !isFresh(items[key], MALICIOUS_TTL_MS);
            return true;
        });
        if (stale.length) chrome.storage.local.remove(stale);
    });
}

chrome.runtime.onInstalled.addListener(pruneCache);
chrome.runtime.onStartup.addListener(pruneCache);
