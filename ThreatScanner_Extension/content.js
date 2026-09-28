const currentUrl = window.location.href;
const hostname = window.location.hostname;

if (hostname === "127.0.0.1" || hostname === "localhost") {
    // Silent pass-through for local testing
} else {

    function generateShapChart(explanation) {
        if (!explanation || Object.keys(explanation).length === 0) return '';
        
        let features = Object.entries(explanation).map(([name, impact]) => ({name, impact}));
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
            const formattedName = f.name.replace(/_/g, ' ').toUpperCase();
            
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
        const shapHtml = generateShapChart(explanation);
        
        document.documentElement.innerHTML = `
            <div style="font-family: Arial, sans-serif; text-align: center; padding: 40px 20px; background-color: #1a0000; min-height: 100vh; color: #ff4d4d; box-sizing: border-box;">
                <h1 style="font-size: 50px; margin-bottom: 10px;">🚨 THREAT DETECTED 🚨</h1>
                <h2 style="color: #ffffff; margin-top: 0;">Access to this website has been blocked.</h2>
                
                <div style="background: #330000; padding: 15px; border-radius: 8px; display: inline-block; margin: 10px 0; border: 1px solid #ff4d4d;">
                    <p style="margin: 5px 0; color: #ccc;"><strong>Target URL:</strong> ${url}</p>
                    <p style="margin: 5px 0; color: #ccc;"><strong>AI Confidence:</strong> ${confidence}%</p>
                </div>
                
                ${shapHtml}
                
                <p style="color: #ccc; max-width: 600px; margin: 0 auto 30px auto; font-size: 14px;">Our machine learning model intercepted this connection and detected structural evasion tactics common in phishing and malware hosting.</p>
                <button onclick="window.location.reload()" style="background-color: #ff4d4d; color: white; border: none; padding: 12px 24px; font-size: 14px; border-radius: 5px; cursor: pointer; font-weight: bold; transition: 0.2s;">I understand the risks, proceed anyway</button>
            </div>
        `;
    }

    // 1. Check Chrome's local storage for the domain
    chrome.storage.local.get([hostname], function(result) {
        if (result[hostname]) {
            if (result[hostname].status === "Malicious") {
                triggerRedAlert(currentUrl, result[hostname].confidence, result[hostname].explanation);
            }
            return;
        }

        // 2. CACHE MISS: Ask the Background Service Worker to fetch (Bypasses Mixed Content!)
        chrome.runtime.sendMessage({ action: "scanUrl", url: currentUrl }, function(response) {
            if (response && response.success) {
                const data = response.data;
                
                const cacheData = {};
                cacheData[hostname] = {
                    status: data.status,
                    confidence: data.confidence,
                    explanation: data.explanation
                };
                chrome.storage.local.set(cacheData);

                if (data.status === "Malicious") {
                    triggerRedAlert(currentUrl, data.confidence, data.explanation);
                }
            } else {
                console.error("ThreatScanner API Error:", response?.error);
            }
        });
    });
}