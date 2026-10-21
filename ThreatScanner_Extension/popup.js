const statusEl = document.getElementById("status");
const hostEl = document.getElementById("host");
const revokeBtn = document.getElementById("revoke");
const rescanBtn = document.getElementById("rescan");

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

document.getElementById("clear-all").addEventListener("click", function() {
    chrome.storage.local.clear(function() {
        setStatus("", "All cached verdicts cleared", "Pages will be rescanned on next visit.");
        revokeBtn.classList.add("hidden");
        rescanBtn.classList.add("hidden");
    });
});

chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    const tab = tabs[0];
    let url;
    try {
        url = new URL(tab.url);
    } catch (e) {
        url = null;
    }

    if (!url || !url.protocol.startsWith("http")) {
        setStatus("", "Not scanned", "ThreatScanner only checks http(s) pages.");
        return;
    }

    hostEl.textContent = url.hostname;
    const keys = {
        allow: allowKey(url.hostname),
        malicious: maliciousKey(normalizeUrl(tab.url)),
        safe: safeKey(url.hostname)
    };

    chrome.storage.local.get(Object.values(keys), function(result) {
        const malicious = result[keys.malicious];
        const safe = result[keys.safe];

        // Same precedence as content.js
        if (result[keys.allow]) {
            setStatus("allowed", "Allowed by you", "You chose to continue to this domain despite a warning.");
            revokeBtn.classList.remove("hidden");
        } else if (isFresh(malicious, MALICIOUS_TTL_MS)) {
            setStatus("malicious", "Blocked", "Malicious score " + Number(malicious.confidence).toFixed(1) + "% · scanned " + formatAge(malicious.timestamp));
            rescanBtn.classList.remove("hidden");
        } else if (isFresh(safe, SAFE_TTL_MS)) {
            setStatus("safe", "Domain safelisted", "Scanned " + formatAge(safe.timestamp));
            rescanBtn.classList.remove("hidden");
        } else {
            setStatus("", "Not scanned yet", "Reload the page to scan it.");
        }
    });

    revokeBtn.addEventListener("click", () => forgetAndReload(tab, [keys.allow]));
    rescanBtn.addEventListener("click", () => forgetAndReload(tab, [keys.malicious, keys.safe]));
});
