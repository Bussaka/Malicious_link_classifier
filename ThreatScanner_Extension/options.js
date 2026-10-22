const apiInput = document.getElementById("api-url");
const apiMessage = document.getElementById("api-message");

let settings = Object.assign({}, DEFAULT_SETTINGS);

function showMessage(text, kind) {
    apiMessage.textContent = text;
    apiMessage.className = "message " + (kind || "");
}

function saveSettings(changes) {
    settings = Object.assign({}, settings, changes);
    return chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

// Accepts "127.0.0.1:8000" or a full URL; returns null for anything that isn't http(s)
function parseApiUrl(text) {
    const value = text.trim().replace(/\/+$/, "");
    try {
        const url = new URL(/^[a-z]+:\/\//i.test(value) ? value : "http://" + value);
        if (!["http:", "https:"].includes(url.protocol)) return null;
        return url.origin + url.pathname.replace(/\/+$/, "");
    } catch (e) {
        return null;
    }
}

function testConnection(apiUrl) {
    showMessage("Connecting…");
    return fetch(apiUrl + "/health", { signal: AbortSignal.timeout(3000) })
        .then(response => {
            if (!response.ok) throw new Error("HTTP " + response.status);
            return response.json();
        })
        .then(info => {
            if (info.status !== "ok") throw new Error("unexpected response");
            showMessage(`Connected: model ${info.model}, blocks above ${(info.threshold * 100).toFixed(1)}%.`, "ok");
            return true;
        })
        .catch(err => {
            showMessage(`No ThreatScanner API answered at ${apiUrl} (${err.message}).`, "error");
            return false;
        });
}

document.getElementById("test").addEventListener("click", () => {
    const apiUrl = parseApiUrl(apiInput.value);
    if (!apiUrl) return showMessage("Enter an http:// or https:// address.", "error");
    testConnection(apiUrl);
});

document.getElementById("save-api").addEventListener("click", () => {
    const apiUrl = parseApiUrl(apiInput.value);
    if (!apiUrl) return showMessage("Enter an http:// or https:// address.", "error");
    apiInput.value = apiUrl;
    // Saved even if the test fails, so the API can be started afterwards; the popup will show it offline
    saveSettings({ apiUrl: apiUrl }).then(() => testConnection(apiUrl)).then(ok => {
        if (ok) showMessage(apiMessage.textContent + " Saved.", "ok");
        else showMessage(apiMessage.textContent + " Saved anyway.", "error");
    });
});

function renderProtection() {
    const paused = isPaused(settings);
    document.getElementById("protection-state").className = "state" + (paused ? " paused" : "");
    let text = "Active";
    if (paused) {
        text = settings.pausedUntil === PAUSED_INDEFINITELY
            ? "Paused until you resume"
            : "Paused until " + new Date(settings.pausedUntil).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });
    }
    document.getElementById("protection-text").textContent = text;
    document.getElementById("pause-controls").classList.toggle("hidden", paused);
    document.getElementById("resume").classList.toggle("hidden", !paused);
}

document.getElementById("pause").addEventListener("click", () => {
    const duration = Number(document.getElementById("pause-duration").value);
    const pausedUntil = duration === PAUSED_INDEFINITELY ? PAUSED_INDEFINITELY : Date.now() + duration;
    saveSettings({ pausedUntil: pausedUntil }).then(renderProtection);
});

document.getElementById("resume").addEventListener("click", () => {
    saveSettings({ pausedUntil: null }).then(renderProtection);
});

function renderStorage(items) {
    const list = document.getElementById("exceptions");
    list.textContent = "";
    const exceptions = Object.keys(items).filter(k => k.startsWith("allow:")).map(k => k.slice("allow:".length)).sort();

    if (exceptions.length === 0) {
        const empty = document.createElement("li");
        empty.className = "empty";
        empty.textContent = "No exceptions.";
        list.appendChild(empty);
    }
    for (const host of exceptions) {
        const item = document.createElement("li");
        const name = document.createElement("code");
        name.textContent = host;
        const remove = document.createElement("button");
        remove.textContent = "Remove";
        remove.addEventListener("click", () => chrome.storage.local.remove(allowKey(host), loadStorage));
        item.append(name, remove);
        list.appendChild(item);
    }

    const safe = Object.keys(items).filter(k => k.startsWith("safe:")).length;
    const blocked = Object.keys(items).filter(k => k.startsWith("malicious:")).length;
    document.getElementById("cache-summary").textContent =
        `${safe} safelisted domain${safe === 1 ? "" : "s"} and ${blocked} blocked page${blocked === 1 ? "" : "s"} are cached. ` +
        "Clearing makes them rescan on the next visit; exceptions and settings are kept.";
}

function loadStorage() {
    chrome.storage.local.get(null, renderStorage);
}

document.getElementById("clear-cache").addEventListener("click", () => {
    chrome.storage.local.get(null, items => {
        chrome.storage.local.remove(Object.keys(items).filter(isVerdictKey), loadStorage);
    });
});

chrome.storage.local.get(SETTINGS_KEY, result => {
    settings = Object.assign({}, DEFAULT_SETTINGS, result[SETTINGS_KEY]);
    apiInput.value = settings.apiUrl;
    renderProtection();
});
loadStorage();
