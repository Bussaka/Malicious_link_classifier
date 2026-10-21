const statusEl = document.getElementById("status");
const hostEl = document.getElementById("host");
const revokeBtn = document.getElementById("revoke");
const rescanBtn = document.getElementById("rescan");

function setStatus(cls, text, detail) {
    statusEl.className = cls;
    statusEl.firstChild.textContent = text;
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
            setStatus("allowed", "⚠️ Allowed by you", "You chose to proceed to this domain despite a warning.");
            revokeBtn.classList.remove("hidden");
        } else if (isFresh(malicious, MALICIOUS_TTL_MS)) {
            setStatus("malicious", "🚨 Blocked", malicious.confidence + "% confidence · scanned " + formatAge(malicious.timestamp));
            rescanBtn.classList.remove("hidden");
        } else if (isFresh(safe, SAFE_TTL_MS)) {
            setStatus("safe", "✅ Domain safelisted", "Scanned " + formatAge(safe.timestamp));
            rescanBtn.classList.remove("hidden");
        } else {
            setStatus("", "Not scanned yet", "Reload the page to scan it.");
        }
    });

    revokeBtn.addEventListener("click", () => forgetAndReload(tab, [keys.allow]));
    rescanBtn.addEventListener("click", () => forgetAndReload(tab, [keys.malicious, keys.safe]));
});
