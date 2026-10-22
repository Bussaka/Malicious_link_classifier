importScripts("cache.js");

// The page stays hidden while a scan runs, so a hung API must not hold it hostage
const SCAN_TIMEOUT_MS = 5000;
const HEALTH_TIMEOUT_MS = 3000;
const HEALTH_ALARM = "api-health";

function getSettings() {
    return chrome.storage.local.get(SETTINGS_KEY)
        .then(result => Object.assign({}, DEFAULT_SETTINGS, result[SETTINGS_KEY]));
}

function apiBase(settings) {
    return settings.apiUrl.replace(/\/+$/, "");
}

// Pages fail open when the API is unreachable, so without this the user would believe they're
// protected while nothing is being scanned. The status lives in storage.session (in memory, not
// touched by cache pruning or clearing) and drives the toolbar badge and the popup.
function setApiStatus(online, details) {
    const status = Object.assign({ online: online, checkedAt: Date.now() }, details);
    return chrome.storage.session.get("apiStatus").then(result => {
        // A scan only reports the threshold; keep the model name from the last health check
        const previous = result.apiStatus;
        const merged = online && previous && previous.online ? Object.assign({}, previous, status) : status;
        return chrome.storage.session.set({ apiStatus: merged }).then(() => {
            updateBadge();
            return merged;
        });
    });
}

// Paused (by the user) takes precedence over offline: both mean pages aren't scanned
function updateBadge() {
    Promise.all([getSettings(), chrome.storage.session.get("apiStatus")]).then(([settings, session]) => {
        const status = session.apiStatus;
        if (isPaused(settings)) {
            chrome.action.setBadgeText({ text: "II" });
            chrome.action.setBadgeBackgroundColor({ color: "#7b8aa1" });
            chrome.action.setTitle({ title: "ThreatScanner Shield: protection paused" });
        } else if (status && !status.online) {
            chrome.action.setBadgeText({ text: "!" });
            chrome.action.setBadgeBackgroundColor({ color: "#c23434" });
            chrome.action.setTitle({ title: "ThreatScanner Shield: API offline, pages are not being scanned" });
        } else {
            chrome.action.setBadgeText({ text: "" });
            chrome.action.setTitle({ title: "ThreatScanner Shield: protection active" });
        }
        chrome.action.setBadgeTextColor({ color: "#ffffff" });
    });
}

function checkHealth() {
    return getSettings()
        .then(settings => fetch(apiBase(settings) + "/health", { signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS) }))
        .then(response => {
            if (!response.ok) throw new Error("API returned HTTP " + response.status);
            return response.json();
        })
        .then(info => setApiStatus(true, { model: info.model, threshold: info.threshold }))
        .catch(err => setApiStatus(false, { error: err.toString() }));
}

// explain: undefined = API default (explain Malicious verdicts), false = score only (faster)
function scanUrl(url, explain) {
    const body = { url: url };
    if (typeof explain === "boolean") body.explain = explain;
    return getSettings()
        .then(settings => fetch(apiBase(settings) + "/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(SCAN_TIMEOUT_MS)
        }))
        .then(response => {
            if (!response.ok) throw new Error("API returned HTTP " + response.status);
            return response.json();
        })
        .then(data => {
            setApiStatus(true, { threshold: data.threshold });
            return data;
        })
        .catch(err => {
            setApiStatus(false, { error: err.toString() });
            throw err;
        });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scanUrl") {
        scanUrl(request.url, request.explain)
            .then(data => sendResponse({ success: true, data: data }))
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        // Returning true tells Chrome we will send the response asynchronously
        return true;
    }

    if (request.action === "checkHealth") {
        checkHealth().then(status => sendResponse(status));
        return true;
    }
});

// Single-page apps change the URL with history.pushState and never reload, so the content
// script would only ever see the first URL. Forward each in-page navigation to its frame.
chrome.webNavigation.onHistoryStateUpdated.addListener(details => {
    chrome.tabs.sendMessage(details.tabId, { action: "urlChanged", url: details.url }, { frameId: details.frameId })
        .catch(() => { /* frame has no content script (e.g. a chrome:// page) */ });
});

// Downloads never render a page, so the content script can't block them. Chrome holds every
// download at the "determining filename" step until listeners answer, so the URL is checked
// there: a small file can't finish before its verdict arrives.
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
    const url = item.finalUrl || item.url;
    if (!isScannable(url)) return;   // blob:, data: - nothing to score; keep Chrome's filename

    lookupVerdict(url, verdict => {
        if (["paused", "allowed", "safe"].includes(verdict.state)) return suggest();
        if (verdict.state === "malicious") return blockDownload(item, url, verdict.entry);

        scanUrl(url, false)
            .then(data => {
                storeVerdict(url, data);
                if (data.status === "Malicious") blockDownload(item, url, data);
                else suggest();
            })
            // Fail open, like pages: an unreachable API must not break every download
            .catch(() => suggest());
    });
    // Tells Chrome suggest() will be called asynchronously
    return true;
});

function blockDownload(item, url, verdict) {
    const host = new URL(url).hostname;
    chrome.downloads.cancel(item.id)
        .then(() => chrome.downloads.erase({ id: item.id }))
        .then(() => notify("Download blocked",
            `A download from ${host} was stopped: its address scored ${Number(verdict.confidence).toFixed(1)}% malicious.`))
        .catch(err => console.error("ThreatScanner could not cancel download:", err));
}

function notify(title, message) {
    chrome.notifications.create({ type: "basic", iconUrl: "icons/icon128.png", title: title, message: message });
}

// Drops expired verdicts and pre-1.2 entries (keyed by bare hostname, no expiry)
function pruneCache() {
    chrome.storage.local.get(null, function(items) {
        const stale = Object.keys(items).filter(key => {
            if (key === SETTINGS_KEY || key.startsWith("allow:")) return false;
            if (key.startsWith("safe:")) return !isFresh(items[key], SAFE_TTL_MS);
            if (key.startsWith("malicious:")) return !isFresh(items[key], MALICIOUS_TTL_MS);
            return true;
        });
        if (stale.length) chrome.storage.local.remove(stale);
    });
}

function onBrowserStart() {
    pruneCache();
    checkHealth();
    // Keeps the badge honest between page loads (API stopped mid-session, a timed pause ending)
    chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: 1 });
}

chrome.runtime.onInstalled.addListener(onBrowserStart);
chrome.runtime.onStartup.addListener(onBrowserStart);

chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === HEALTH_ALARM) checkHealth();
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes[SETTINGS_KEY]) return;
    // A new API address needs a fresh health check; a pause change needs the badge updated
    checkHealth();
});
