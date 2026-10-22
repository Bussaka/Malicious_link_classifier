const currentUrl = window.location.href;
const hostname = window.location.hostname;
// The script also runs in embedded frames (all_frames), which get a compact block notice
const isTopFrame = window === window.top;

if (hostname === "127.0.0.1" || hostname === "localhost" || !isScannable(currentUrl)) {
    // Silent pass-through for local testing and non-web frames (about:blank, data:, file:)
} else {

    // Shared look for the scanning notice and block page: white surfaces, blue brand,
    // red only for the threat itself. System fonts, so a blocked page makes no extra requests.
    const FONT = "'Segoe UI', system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif";
    const MONO = "ui-monospace, 'Cascadia Mono', Consolas, 'SF Mono', monospace";

    const SHIELD_PATH = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>';
    function icon(paths, size) {
        return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
    }

    // Hide the page from document_start until we have a verdict, so a malicious page
    // can't be seen or interacted with while the scan is in flight. Scripts on the page
    // still run - content scripts can't pause navigation, only hide its result.
    // The notice styles live here too; visibility: visible overrides the hidden <html> for it alone.
    const guardStyle = document.createElement("style");
    guardStyle.textContent = `
        html { visibility: hidden !important; }
        #ts-scanning { visibility: visible !important; position: fixed; inset: 0; z-index: 2147483647;
            display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px;
            background: #ffffff; color: #0f2747; font: 500 15px ${FONT}; }
        #ts-scanning .ts-ring { position: relative; width: 56px; height: 56px; color: #256abf;
            display: flex; align-items: center; justify-content: center; }
        #ts-scanning .ts-ring::before { content: ""; position: absolute; inset: 0; border-radius: 50%;
            border: 3px solid #e1ecfa; border-top-color: #256abf; animation: ts-spin 0.9s linear infinite; }
        #ts-scanning .ts-sub { color: #4a5d78; font-weight: 400; font-size: 13px; margin-top: -10px; }
        @keyframes ts-spin { to { transform: rotate(360deg); } }
    `;
    document.documentElement.appendChild(guardStyle);

    // Only shown when the scan is slow, so fast verdicts don't flash an overlay - and only for
    // the page itself; embedded frames (ads, widgets) just stay hidden until their verdict
    const scanningNotice = document.createElement("div");
    scanningNotice.id = "ts-scanning";
    scanningNotice.innerHTML = `
        <div class="ts-ring">${icon(SHIELD_PATH, 22)}</div>
        <div>Checking this page</div>
        <div class="ts-sub">ThreatScanner is analyzing the address before it opens</div>`;
    const noticeTimer = isTopFrame
        ? setTimeout(() => document.documentElement.appendChild(scanningNotice), 300)
        : null;

    function revealPage() {
        clearTimeout(noticeTimer);
        scanningNotice.remove();
        guardStyle.remove();
    }

    // Everything interpolated into the block screen's innerHTML goes through here,
    // since the URL is attacker-controlled
    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    // Human-readable names for the model's features (kept in step with app.py)
    const FEATURE_LABELS = {
        url_length: "URL length", domain_length: "Domain length", path_length: "Path length",
        num_digits: "Digit count", num_special_chars: "Special characters", has_ip: "IP address as host",
        num_suspicious_words: "Sensitive keywords", domain_entropy: "Domain randomness",
        tld_length: "TLD length", is_suspicious_tld: "High-risk TLD", num_encoded_chars: "Encoded characters",
        directory_depth: "Directory depth", subdomain_count: "Subdomain depth", query_length: "Query length",
        num_query_params: "Query parameters", host_digit_ratio: "Digits in host", num_host_hyphens: "Hyphens in host",
        has_port: "Explicit port", has_at_in_host: "Credentials in host", brand_in_host: "Brand outside its domain",
        brand_in_path: "Brand name in path"
    };

    function prettyName(name) {
        // Character n-grams (e.g. 'ngram "ogin."') keep their exact text - case and punctuation are the point
        if (name.startsWith("ngram ")) return "Text pattern " + name.slice(6);
        return FEATURE_LABELS[name] || name.replace(/_/g, " ");
    }

    // Diverging bars around a center line: red pushes toward malicious, blue toward safe
    function generateExplanationChart(explanation) {
        if (!explanation || Object.keys(explanation).length === 0) return "";

        let features = Object.entries(explanation)
            .map(([name, impact]) => ({ name, impact: Number(impact) || 0 }))
            .filter(f => f.impact !== 0);
        features.sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));
        features = features.slice(0, 7);
        if (features.length === 0) return "";

        let maxAbs = Math.max(...features.map(f => Math.abs(f.impact)));
        if (maxAbs === 0) maxAbs = 1;

        const rows = features.map(f => {
            const half = (Math.abs(f.impact) / maxAbs) * 50;
            const toMalicious = f.impact > 0;
            const label = escapeHtml(prettyName(f.name));
            const tooltip = `${label}: ${toMalicious ? "+" : ""}${f.impact.toFixed(4)} ${toMalicious ? "toward malicious" : "toward safe"}`;
            const bar = toMalicious
                ? `left: 50%; width: ${half}%; background: #e34948; border-radius: 0 4px 4px 0;`
                : `right: 50%; width: ${half}%; background: #2a78d6; border-radius: 4px 0 0 4px;`;
            return `
                <div class="ts-row" title="${tooltip}">
                    <div class="ts-row-label">${label}</div>
                    <div class="ts-row-track"><div class="ts-row-bar" style="${bar}"></div></div>
                </div>`;
        }).join("");

        return `
            <section class="ts-card">
                <div class="ts-card-head">
                    <h2>Why it was flagged</h2>
                    <div class="ts-legend">
                        <span><i style="background:#e34948"></i>Toward malicious</span>
                        <span><i style="background:#2a78d6"></i>Toward safe</span>
                    </div>
                </div>
                <div class="ts-rows">${rows}</div>
            </section>`;
    }

    function blockPageStyles() {
        return `
            html, body { margin: 0; padding: 0; background: #ffffff; }
            #ts-root, #ts-root * { box-sizing: border-box; margin: 0; padding: 0; }
            #ts-root { min-height: 100vh; font-family: ${FONT}; color: #0f2747; background: #ffffff; font-size: 15px; line-height: 1.5; }
            #ts-root .ts-topbar { height: 56px; display: flex; align-items: center; gap: 10px; padding: 0 28px;
                border-bottom: 1px solid #e8eef7; color: #256abf; }
            #ts-root .ts-wordmark { font-weight: 700; font-size: 16px; color: #0f2747; letter-spacing: -0.01em; }
            #ts-root .ts-wordmark span { color: #256abf; }
            #ts-root .ts-main { max-width: 680px; margin: 0 auto; padding: 56px 24px 64px; }
            #ts-root .ts-alert-icon { width: 60px; height: 60px; border-radius: 50%; background: #fbe1e1; color: #c23434;
                display: flex; align-items: center; justify-content: center; margin-bottom: 24px; }
            #ts-root h1 { font-size: 30px; font-weight: 600; letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 12px; }
            #ts-root .ts-lede { color: #4a5d78; font-size: 16px; max-width: 600px; }
            #ts-root .ts-label { font-size: 11px; font-weight: 600; letter-spacing: 0.07em; text-transform: uppercase; color: #7b8aa1; margin-bottom: 6px; }
            #ts-root .ts-url { font-family: ${MONO}; font-size: 13px; background: #f4f8fd; border: 1px solid #dce6f2;
                border-radius: 8px; padding: 11px 13px; word-break: break-all; color: #0f2747; }
            #ts-root .ts-block { margin-top: 28px; }
            #ts-root .ts-meter-head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px; }
            #ts-root .ts-score { font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }
            #ts-root .ts-meter-note { color: #4a5d78; font-size: 13px; }
            #ts-root .ts-track { position: relative; height: 8px; border-radius: 999px; background: #e8eef7; }
            #ts-root .ts-fill { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 999px; background: #e34948; }
            #ts-root .ts-tick { position: absolute; top: -4px; bottom: -4px; width: 2px; background: #0f2747; border-radius: 1px; }
            #ts-root .ts-card { margin-top: 28px; border: 1px solid #dce6f2; border-radius: 12px; padding: 20px 22px; }
            #ts-root .ts-card-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
            #ts-root .ts-card h2 { font-size: 15px; font-weight: 600; }
            #ts-root .ts-legend { display: flex; gap: 14px; font-size: 12px; color: #4a5d78; }
            #ts-root .ts-legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; }
            #ts-root .ts-rows { display: flex; flex-direction: column; gap: 10px; }
            #ts-root .ts-row { display: grid; grid-template-columns: 38% 1fr; align-items: center; gap: 14px; font-size: 13px; }
            #ts-root .ts-row-label { text-align: right; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #0f2747; }
            #ts-root .ts-row-track { position: relative; height: 14px; }
            #ts-root .ts-row-track::before { content: ""; position: absolute; left: 50%; top: -3px; bottom: -3px; width: 1px; background: #c5d2e3; }
            #ts-root .ts-row-bar { position: absolute; top: 0; bottom: 0; }
            #ts-root .ts-actions { margin-top: 32px; display: flex; gap: 12px; flex-wrap: wrap; }
            #ts-root button { font-family: ${FONT}; font-size: 14px; font-weight: 600; border-radius: 8px; padding: 11px 20px; cursor: pointer; }
            #ts-root .ts-primary { background: #256abf; color: #ffffff; border: 1px solid #256abf; }
            #ts-root .ts-primary:hover { background: #1c5cab; }
            #ts-root .ts-secondary { background: #ffffff; color: #256abf; border: 1px solid #c5d6ee; }
            #ts-root .ts-secondary:hover { background: #f4f8fd; }
            #ts-root .ts-advanced { display: none; margin-top: 20px; padding: 16px 18px; border-radius: 10px; background: #f4f8fd; color: #4a5d78; font-size: 14px; }
            #ts-root .ts-advanced.open { display: block; }
            #ts-root .ts-link { background: none; border: none; padding: 0; margin-top: 8px; color: #c23434; text-decoration: underline; font-weight: 500; }
            #ts-root .ts-pending { color: #7b8aa1; font-size: 13px; }
            #ts-root .ts-footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e8eef7; color: #7b8aa1; font-size: 12px; }
        `;
    }

    function triggerBlockPage(url, confidence, explanation, threshold) {
        window.stop();
        revealPage();

        const score = Math.min(Math.max(Number(confidence) || 0, 0), 100);
        const tick = Number.isFinite(Number(threshold)) && threshold !== null && threshold !== undefined
            ? `<div class="ts-tick" style="left: ${Number(threshold) * 100}%" title="Block threshold ${(Number(threshold) * 100).toFixed(1)}%"></div>`
            : "";
        const thresholdNote = tick ? `Blocked above ${(Number(threshold) * 100).toFixed(1)}%` : "Above the block threshold";

        if (!isTopFrame) {
            renderFrameBlock(score);
            return;
        }
        // Verdicts arrive without an explanation (scans ask for the score only, to block sooner),
        // so the chart is fetched after the block page is up
        const hasExplanation = Boolean(explanation && Object.keys(explanation).length);

        document.documentElement.innerHTML = `
            <head><meta charset="utf-8"><title>Page blocked | ThreatScanner</title><style>${blockPageStyles()}</style></head>
            <body>
            <div id="ts-root">
                <header class="ts-topbar">
                    ${icon(SHIELD_PATH, 22)}
                    <div class="ts-wordmark">Threat<span>Scanner</span></div>
                </header>
                <main class="ts-main">
                    <div class="ts-alert-icon">${icon(SHIELD_PATH + '<path d="M12 8v4"/><path d="M12 16h.01"/>', 30)}</div>
                    <h1>This page has been blocked</h1>
                    <p class="ts-lede">The address of this page has the structure of phishing or malware links, so ThreatScanner
                        stopped it from loading. Attackers use pages like this to steal passwords and card details or to install software.</p>

                    <div class="ts-block">
                        <div class="ts-label">Blocked address</div>
                        <div class="ts-url">${escapeHtml(url)}</div>
                    </div>

                    <div class="ts-block">
                        <div class="ts-meter-head">
                            <div><div class="ts-label">Malicious score</div><div class="ts-score">${escapeHtml(score.toFixed(1))}%</div></div>
                            <div class="ts-meter-note">${thresholdNote}</div>
                        </div>
                        <div class="ts-track"><div class="ts-fill" style="width: ${score}%"></div>${tick}</div>
                    </div>

                    <div id="ts-why">${hasExplanation
                        ? generateExplanationChart(explanation)
                        : `<section class="ts-card"><div class="ts-card-head"><h2>Why it was flagged</h2></div>
                           <p class="ts-pending">Working out which parts of the address raised the score&hellip;</p></section>`}</div>

                    <div class="ts-actions">
                        <button class="ts-primary" id="threatscanner-back">Back to safety</button>
                        <button class="ts-secondary" id="threatscanner-advanced">Details</button>
                    </div>
                    <div class="ts-advanced" id="threatscanner-advanced-panel">
                        <p>ThreatScanner judges the address only, so legitimate pages are occasionally blocked. If you trust
                        this site, you can continue. You won't be warned about ${escapeHtml(hostname)} again until you remove the
                        exception from the toolbar popup.</p>
                        <button class="ts-link" id="threatscanner-proceed">Continue to ${escapeHtml(hostname)} (unsafe)</button>
                    </div>

                    <div class="ts-footer">Verdict from your local ThreatScanner API. Manage exceptions and cached verdicts from the toolbar popup.</div>
                </main>
            </div>
            </body>
        `;

        // Bound here rather than inline so the page's CSP can't block them
        document.getElementById("threatscanner-back").addEventListener("click", function() {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.replace("about:blank");
            }
        });

        document.getElementById("threatscanner-advanced").addEventListener("click", function() {
            document.getElementById("threatscanner-advanced-panel").classList.toggle("open");
        });

        document.getElementById("threatscanner-proceed").addEventListener("click", function() {
            const allowData = {};
            allowData[allowKey(hostname)] = true;
            chrome.storage.local.set(allowData, function() {
                window.location.reload();
            });
        });

        if (!hasExplanation) {
            // requestScan also re-caches the verdict, now with its explanation
            requestScan(url, data => {
                const why = document.getElementById("ts-why");
                if (!why) return;
                why.innerHTML = data && data.explanation ? generateExplanationChart(data.explanation) : "";
            }, true);
        }
    }

    // Embedded frames are often small, so they get a compact notice instead of the full page
    function renderFrameBlock(score) {
        document.documentElement.innerHTML = `
            <head><meta charset="utf-8"><style>
                html, body { margin: 0; height: 100%; background: #ffffff; }
                #ts-frame { box-sizing: border-box; height: 100%; min-height: 60px; display: flex; flex-direction: column;
                    align-items: center; justify-content: center; gap: 6px; padding: 12px; text-align: center;
                    font: 13px ${FONT}; color: #4a5d78; border: 1px solid #f3caca; background: #fdf6f6; }
                #ts-frame strong { color: #c23434; font-weight: 600; display: flex; align-items: center; gap: 6px; }
                #ts-frame button { font: 500 12px ${FONT}; color: #256abf; background: none; border: none;
                    text-decoration: underline; cursor: pointer; padding: 0; }
            </style></head>
            <body><div id="ts-frame">
                <strong>${icon(SHIELD_PATH + '<path d="M12 8v4"/><path d="M12 16h.01"/>', 16)} Embedded content blocked</strong>
                <div>Content from ${escapeHtml(hostname)} scored ${escapeHtml(score.toFixed(1))}% malicious.</div>
                <button id="threatscanner-proceed">Show anyway</button>
            </div></body>`;

        document.getElementById("threatscanner-proceed").addEventListener("click", function() {
            const allowData = {};
            allowData[allowKey(hostname)] = true;
            chrome.storage.local.set(allowData, () => window.location.reload());
        });
    }

    // explain: false for link checks - they only need the score, and skipping the explanation
    // makes a flagged link's verdict arrive ~0.7s sooner
    function requestScan(url, callback, explain) {
        // The background worker makes the request, which bypasses page CSP and mixed-content rules
        chrome.runtime.sendMessage({ action: "scanUrl", url: url, explain: explain }, function(response) {
            // Read lastError so Chrome doesn't log "Unchecked runtime.lastError"
            // when the extension was reloaded under an open tab
            const messagingError = chrome.runtime.lastError;
            if (response && response.success) {
                storeVerdict(url, response.data);
                callback(response.data);
            } else {
                console.error("ThreatScanner API Error:", response?.error || messagingError?.message);
                callback(null);
            }
        });
    }

    // Checks the page (or frame) at url: on first load the page is hidden until this resolves;
    // for in-page navigations it is already showing and only gets replaced if flagged
    let lastCheckedUrl = null;
    function checkPage(url) {
        lastCheckedUrl = normalizeUrl(url);
        lookupVerdict(url, verdict => {
            if (verdict.state === "malicious") {
                const e = verdict.entry;
                return triggerBlockPage(url, e.confidence, e.explanation, e.threshold);
            }
            if (verdict.state !== "unknown") return revealPage();   // paused, allowed or safe

            // Verdict first, without the explanation: the block page appears ~0.7s sooner and
            // fills in "Why it was flagged" when the explanation arrives
            requestScan(url, data => {
                if (data && data.status === "Malicious") {
                    triggerBlockPage(url, data.confidence, data.explanation, data.threshold);
                } else {
                    // Safe, or fail open: an unreachable API shouldn't make the whole web unusable
                    revealPage();
                }
            }, false);
        });
    }

    checkPage(currentUrl);

    // Single-page apps change the URL without reloading; background.js forwards each change
    chrome.runtime.onMessage.addListener(message => {
        if (message.action === "urlChanged" && normalizeUrl(message.url) !== lastCheckedUrl) {
            checkPage(message.url);
        }
    });

    // --- Link checks -------------------------------------------------------------------------
    // Checking a link only when it is clicked would mean holding the navigation hostage to an
    // API call. Instead links are checked while the pointer rests on them, so by the time of
    // the click the verdict is usually known. Pages that open anyway are still blocked on
    // arrival; this mainly guards the cases that never render a page, like file downloads.
    const HOVER_DELAY_MS = 150;
    const linkVerdicts = new Map();   // normalized URL -> { state, entry }
    let hoverTimer = null;

    function linkFromEvent(event) {
        const target = event.target instanceof Element ? event.target : null;
        const link = target && target.closest("a[href]");
        return link && isScannable(link.href) ? link : null;
    }

    function precheckLink(url) {
        const key = normalizeUrl(url);
        if (linkVerdicts.has(key)) return;
        linkVerdicts.set(key, { state: "pending" });

        lookupVerdict(url, verdict => {
            if (verdict.state !== "unknown") {
                linkVerdicts.set(key, verdict);
                return;
            }
            requestScan(url, data => {
                if (!data) {
                    linkVerdicts.delete(key);   // API trouble: try again on the next hover
                } else {
                    linkVerdicts.set(key, data.status === "Malicious"
                        ? { state: "malicious", entry: data }
                        : { state: "safe" });
                }
            }, false);
        });
    }

    function onPointerOver(event) {
        const link = linkFromEvent(event);
        clearTimeout(hoverTimer);
        if (link) hoverTimer = setTimeout(() => precheckLink(link.href), HOVER_DELAY_MS);
    }

    function onLinkActivate(event) {
        if (event.defaultPrevented || event.button > 1) return;
        const link = linkFromEvent(event);
        if (!link) return;
        const verdict = linkVerdicts.get(normalizeUrl(link.href));
        if (verdict && verdict.state === "malicious") {
            event.preventDefault();
            event.stopImmediatePropagation();
            const newTab = link.target === "_blank" || event.ctrlKey || event.metaKey || event.shiftKey || event.button === 1;
            showLinkWarning(link.href, verdict.entry, newTab);
        }
    }

    document.addEventListener("mouseover", onPointerOver, true);
    document.addEventListener("focusin", onPointerOver, true);     // keyboard users tab onto links
    document.addEventListener("click", onLinkActivate, true);
    document.addEventListener("auxclick", onLinkActivate, true);   // middle-click opens a new tab

    // An in-page dialog in a closed shadow root, so the page's own CSS and scripts can't restyle it
    function showLinkWarning(url, entry, newTab) {
        const linkHost = new URL(url).hostname;
        const score = Math.min(Math.max(Number(entry.confidence) || 0, 0), 100);
        const host = document.createElement("div");
        const shadow = host.attachShadow({ mode: "closed" });
        shadow.innerHTML = `
            <style>
                .backdrop { position: fixed; inset: 0; z-index: 2147483647; background: rgba(15, 39, 71, 0.45);
                    display: flex; align-items: center; justify-content: center; padding: 16px; font: 14px/1.5 ${FONT}; }
                .dialog { background: #ffffff; color: #0f2747; border-radius: 12px; max-width: 460px; width: 100%;
                    padding: 24px; box-shadow: 0 20px 50px rgba(15, 39, 71, 0.25); }
                .icon { width: 44px; height: 44px; border-radius: 50%; background: #fbe1e1; color: #c23434;
                    display: flex; align-items: center; justify-content: center; margin-bottom: 14px; }
                h2 { margin: 0 0 6px; font-size: 18px; font-weight: 600; }
                p { margin: 0; color: #4a5d78; }
                .url { margin: 14px 0 20px; font: 12px ${MONO}; background: #f4f8fd; border: 1px solid #dce6f2;
                    border-radius: 8px; padding: 9px 11px; word-break: break-all; }
                .actions { display: flex; gap: 10px; justify-content: flex-end; flex-wrap: wrap; }
                button { font: 600 13px ${FONT}; border-radius: 8px; padding: 9px 16px; cursor: pointer; }
                .stay { background: #256abf; color: #ffffff; border: 1px solid #256abf; }
                .open { background: #ffffff; color: #c23434; border: 1px solid #f3caca; }
            </style>
            <div class="backdrop" role="alertdialog" aria-modal="true" aria-labelledby="t">
                <div class="dialog">
                    <div class="icon">${icon(SHIELD_PATH + '<path d="M12 8v4"/><path d="M12 16h.01"/>', 22)}</div>
                    <h2 id="t">This link looks dangerous</h2>
                    <p>ThreatScanner flagged where this link leads as likely phishing or malware
                       (malicious score ${escapeHtml(score.toFixed(1))}%).</p>
                    <div class="url">${escapeHtml(url)}</div>
                    <div class="actions">
                        <button class="open">Open anyway</button>
                        <button class="stay">Stay on this page</button>
                    </div>
                </div>
            </div>`;
        document.documentElement.appendChild(host);

        const onKey = e => { if (e.key === "Escape") close(); };
        const close = () => { host.remove(); document.removeEventListener("keydown", onKey, true); };
        document.addEventListener("keydown", onKey, true);
        shadow.querySelector(".stay").addEventListener("click", close);
        shadow.querySelector(".backdrop").addEventListener("click", e => { if (e.target === e.currentTarget) close(); });
        shadow.querySelector(".stay").focus();
        shadow.querySelector(".open").addEventListener("click", () => {
            // Same as "proceed anyway" on the block page: an exception for that domain
            const allowData = {};
            allowData[allowKey(linkHost)] = true;
            chrome.storage.local.set(allowData, () => {
                close();
                if (newTab) window.open(url, "_blank", "noopener");
                else window.location.assign(url);
            });
        });
    }
}
