const currentUrl = window.location.href;
const hostname = window.location.hostname;

if (hostname === "127.0.0.1" || hostname === "localhost") {
    // Silent pass-through for local testing
} else {

    // Hide the page from document_start until we have a verdict, so a malicious page
    // can't be seen or interacted with while the scan is in flight. Scripts on the page
    // still run - content scripts can't pause navigation, only hide its result.
    const guardStyle = document.createElement("style");
    guardStyle.textContent = "html { visibility: hidden !important; }";
    document.documentElement.appendChild(guardStyle);

    // Only shown when the scan is slow, so fast verdicts don't flash an overlay.
    // visibility: visible overrides the hidden <html> for this element alone.
    const scanningNotice = document.createElement("div");
    scanningNotice.textContent = "🛡️ ThreatScanner is checking this page…";
    scanningNotice.style.cssText = "visibility: visible !important; position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; background: #1a1a1a; color: #ddd; font: 16px Arial, sans-serif; z-index: 2147483647;";
    const noticeTimer = setTimeout(() => document.documentElement.appendChild(scanningNotice), 300);

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

    function generateShapChart(explanation) {
        if (!explanation || Object.keys(explanation).length === 0) return '';
        
        let features = Object.entries(explanation).map(([name, impact]) => ({name, impact: Number(impact) || 0}));
        features.sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));
        features = features.slice(0, 7);
        
        let maxAbs = Math.max(...features.map(f => Math.abs(f.impact)));
        if (maxAbs === 0) maxAbs = 1;

        let chartHtml = `
        <div style="background: #220000; padding: 20px; border-radius: 8px; margin: 20px auto; max-width: 600px; border: 1px solid #550000; text-align: left;">
            <h3 style="color: #fff; margin-top: 0; margin-bottom: 15px; font-size: 18px; text-align: center;">🧠 AI Decision Breakdown (SHAP)</h3>
            <p style="color: #aaa; font-size: 13px; text-align: center; margin-bottom: 20px;">
                <span style="color: #ff4d4d; font-weight: bold;">■ Pushed toward Malicious</span> &nbsp;&nbsp;&nbsp;&nbsp; 
                <span style="color: #4da6ff; font-weight: bold;">■ Pulled toward Safe</span>
            </p>
            <div style="display: flex; flex-direction: column; gap: 12px;">
        `;

        features.forEach(f => {
            const widthPct = (Math.abs(f.impact) / maxAbs) * 100;
            const color = f.impact > 0 ? '#ff4d4d' : '#4da6ff'; 
            // Character n-grams (e.g. 'ngram "ogin."') are shown verbatim - case and
            // punctuation are the point; feature names like domain_entropy are prettified
            const formattedName = escapeHtml(f.name.startsWith('ngram ')
                ? f.name
                : f.name.replace(/_/g, ' ').toUpperCase());
            
            chartHtml += `
                <div style="display: flex; align-items: center; justify-content: space-between; font-size: 12px; color: #ddd; font-family: monospace;">
                    <div style="width: 35%; text-align: right; padding-right: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${formattedName}">${formattedName}</div>
                    <div style="width: 65%; background: #440000; border-radius: 3px; height: 18px; position: relative;">
                        <div style="width: ${widthPct}%; background-color: ${color}; height: 100%; border-radius: 3px; box-shadow: 0 0 5px ${color}44;"></div>
                    </div>
                </div>
            `;
        });

        chartHtml += `</div></div>`;
        return chartHtml;
    }

    function triggerRedAlert(url, confidence, explanation) {
        window.stop();
        revealPage();
        const shapHtml = generateShapChart(explanation);
        
        document.documentElement.innerHTML = `
            <div style="font-family: Arial, sans-serif; text-align: center; padding: 40px 20px; background-color: #1a0000; min-height: 100vh; color: #ff4d4d; box-sizing: border-box;">
                <h1 style="font-size: 50px; margin-bottom: 10px;">🚨 THREAT DETECTED 🚨</h1>
                <h2 style="color: #ffffff; margin-top: 0;">Access to this website has been blocked.</h2>
                
                <div style="background: #330000; padding: 15px; border-radius: 8px; display: inline-block; margin: 10px 0; border: 1px solid #ff4d4d;">
                    <p style="margin: 5px 0; color: #ccc;"><strong>Target URL:</strong> ${escapeHtml(url)}</p>
                    <p style="margin: 5px 0; color: #ccc;"><strong>AI Confidence:</strong> ${escapeHtml(Number(confidence))}%</p>
                </div>
                
                ${shapHtml}
                
                <p style="color: #ccc; max-width: 600px; margin: 0 auto 30px auto; font-size: 14px;">Our machine learning model intercepted this connection and detected structural evasion tactics common in phishing and malware hosting.</p>
                <button id="threatscanner-proceed" style="background-color: #ff4d4d; color: white; border: none; padding: 12px 24px; font-size: 14px; border-radius: 5px; cursor: pointer; font-weight: bold; transition: 0.2s;">I understand the risks, proceed anyway</button>
            </div>
        `;

        // Bound here rather than inline so the page's CSP can't block it
        document.getElementById("threatscanner-proceed").addEventListener("click", function() {
            const allowData = {};
            allowData[allowKey(hostname)] = true;
            chrome.storage.local.set(allowData, function() {
                window.location.reload();
            });
        });
    }

    const pageUrl = normalizeUrl(currentUrl);
    const keys = {
        allow: allowKey(hostname),
        malicious: maliciousKey(pageUrl),
        safe: safeKey(hostname)
    };

    // 1. Check Chrome's local storage (see cache.js for the layout)
    chrome.storage.local.get(Object.values(keys), function(result) {
        // User already chose to proceed to this domain
        if (result[keys.allow]) {
            revealPage();
            return;
        }

        // Checked before the domain safelist so a blocked page stays blocked
        // even after a different page on the same domain scans Safe
        const cached = result[keys.malicious];
        if (isFresh(cached, MALICIOUS_TTL_MS)) {
            triggerRedAlert(currentUrl, cached.confidence, cached.explanation);
            return;
        }

        if (isFresh(result[keys.safe], SAFE_TTL_MS)) {
            revealPage();
            return;
        }

        // 2. CACHE MISS: Ask the Background Service Worker to fetch (Bypasses Mixed Content!)
        chrome.runtime.sendMessage({ action: "scanUrl", url: currentUrl }, function(response) {
            // Read lastError so Chrome doesn't log "Unchecked runtime.lastError"
            // when the extension was reloaded under an open tab
            const messagingError = chrome.runtime.lastError;

            if (response && response.success) {
                const data = response.data;

                // Safe verdicts trust the whole domain; Malicious ones only block this page,
                // so one bad URL doesn't condemn every other page on the site
                const cacheData = {};
                if (data.status === "Malicious") {
                    cacheData[keys.malicious] = {
                        confidence: data.confidence,
                        explanation: data.explanation,
                        timestamp: Date.now()
                    };
                } else {
                    cacheData[keys.safe] = { timestamp: Date.now() };
                }
                chrome.storage.local.set(cacheData);

                if (data.status === "Malicious") {
                    triggerRedAlert(currentUrl, data.confidence, data.explanation);
                } else {
                    revealPage();
                }
            } else {
                // Fail open: an unreachable API shouldn't make the whole web unusable
                console.error("ThreatScanner API Error:", response?.error || messagingError?.message);
                revealPage();
            }
        });
    });
}