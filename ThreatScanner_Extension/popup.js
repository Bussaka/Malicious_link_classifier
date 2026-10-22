const statusEl = document.getElementById("status");
const hostEl = document.getElementById("host");
const revokeBtn = document.getElementById("revoke");
const rescanBtn = document.getElementById("rescan");
const pauseBtn = document.getElementById("pause");
const resumeBtn = document.getElementById("resume");

const PAUSE_MS = 60 * 60 * 1000;

// Line icons drawn inside the shield outline; static markup, never user data
const SHIELD = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>';
const STATUS_ICONS = {
    safe: SHIELD + '<path d="m9 12 2 2 4-4"/>',
    malicious: SHIELD + '<path d="M12 8v4"/><path d="M12 16h.01"/>',
    allowed: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    "": SHIELD
};

function setStatus(cls, text, detail) {
    statusEl.className = cls;
    document.getElementById("status-icon").innerHTML =
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + STATUS_ICONS[cls] + '</svg>';
    document.getElementById("status-title").textContent = text;
    document.getElementById("detail").textContent = detail || "";
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

// Top bar: is the shield actually scanning? Paused-by-you wins over the API state.
function renderProtection(settings, status) {
    const apiEl = document.getElementById("api");
    const title = document.getElementById("api-title");
    const detail = document.getElementById("api-detail");
    const help = document.getElementById("api-offline-help");
    help.classList.add("hidden");

    pauseBtn.classList.toggle("hidden", isPaused(settings));
    resumeBtn.classList.toggle("hidden", !isPaused(settings));

    if (isPaused(settings)) {
        apiEl.className = "paused";
        title.textContent = "Protection paused";
        detail.textContent = settings.pausedUntil === PAUSED_INDEFINITELY
            ? "Pages open without being scanned until you resume."
            : "Pages open without being scanned until " + formatTime(settings.pausedUntil) + ".";
    } else if (!status) {
        apiEl.className = "";
        title.textContent = "Checking protection…";
        detail.textContent = "";
    } else if (status.online) {
        apiEl.className = "online";
        title.textContent = "Protection active";
        const parts = [];
        if (status.model) parts.push("Model " + status.model);
        if (typeof status.threshold === "number") parts.push("blocks above " + (status.threshold * 100).toFixed(1) + "%");
        detail.textContent = parts.join(" · ");
    } else {
        apiEl.className = "offline";
        title.textContent = "Protection paused: API offline";
        detail.textContent = "";
        document.getElementById("api-url").textContent = settings.apiUrl;
        help.classList.remove("hidden");
    }
}

let currentSettings = Object.assign({}, DEFAULT_SETTINGS);
let currentStatus = null;

function refreshProtection() {
    renderProtection(currentSettings, currentStatus);
}

// Show the last known state at once, then replace it with a fresh health check
chrome.storage.local.get(SETTINGS_KEY, result => {
    currentSettings = Object.assign({}, DEFAULT_SETTINGS, result[SETTINGS_KEY]);
    chrome.storage.session.get("apiStatus", session => {
        currentStatus = session.apiStatus || null;
        refreshProtection();
        chrome.runtime.sendMessage({ action: "checkHealth" }, status => {
            currentStatus = status;
            refreshProtection();
        });
    });
});

function saveSettings(changes) {
    currentSettings = Object.assign({}, currentSettings, changes);
    chrome.storage.local.set({ [SETTINGS_KEY]: currentSettings }, refreshProtection);
}

pauseBtn.addEventListener("click", () => saveSettings({ pausedUntil: Date.now() + PAUSE_MS }));
resumeBtn.addEventListener("click", () => saveSettings({ pausedUntil: null }));

document.getElementById("api-retry").addEventListener("click", function() {
    document.getElementById("api-title").textContent = "Checking protection…";
    chrome.runtime.sendMessage({ action: "checkHealth" }, status => {
        currentStatus = status;
        refreshProtection();
    });
});

document.getElementById("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());

function formatAge(timestamp) {
    const hours = Math.floor((Date.now() - timestamp) / 3600000);
    if (hours < 1) return "less than an hour ago";
    if (hours < 48) return hours + "h ago";
    return Math.floor(hours / 24) + " days ago";
}

// Clears every verdict and exception that could apply to this tab, then reloads it
function forgetAndReload(tab, keys) {
    chrome.storage.local.remove(keys, function() {
        chrome.tabs.reload(tab.id);
        window.close();
    });
}

// Only cached verdicts: exceptions you chose and your settings are kept
document.getElementById("clear-all").addEventListener("click", function() {
    chrome.storage.local.get(null, items => {
        chrome.storage.local.remove(Object.keys(items).filter(isVerdictKey), () => {
            setStatus("", "Cached verdicts cleared", "Pages will be rescanned on your next visit.");
            revokeBtn.classList.add("hidden");
            rescanBtn.classList.add("hidden");
        });
    });
});

chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    const tab = tabs[0];
    if (!tab || !isScannable(tab.url || "")) {
        setStatus("", "Not scanned", "ThreatScanner only checks http(s) pages.");
        return;
    }

    hostEl.textContent = new URL(tab.url).hostname;
    const keys = verdictKeys(tab.url);

    // Same precedence as the content script, via the shared lookupVerdict
    lookupVerdict(tab.url, verdict => {
        if (verdict.state === "paused") {
            setStatus("", "Not being scanned", "Protection is paused.");
        } else if (verdict.state === "allowed") {
            setStatus("allowed", "Allowed by you", "You chose to continue to this domain despite a warning.");
            revokeBtn.classList.remove("hidden");
        } else if (verdict.state === "malicious") {
            setStatus("malicious", "Blocked", "Malicious score " + Number(verdict.entry.confidence).toFixed(1) +
                "% · scanned " + formatAge(verdict.entry.timestamp));
            rescanBtn.classList.remove("hidden");
        } else if (verdict.state === "safe") {
            setStatus("safe", "Domain safelisted", "Scanned " + formatAge(verdict.entry.timestamp));
            rescanBtn.classList.remove("hidden");
        } else {
            setStatus("", "Not scanned yet", "Reload the page to scan it.");
        }
    });

    revokeBtn.addEventListener("click", () => forgetAndReload(tab, [keys.allow]));
    rescanBtn.addEventListener("click", () => forgetAndReload(tab, [keys.malicious, keys.safe]));
});
