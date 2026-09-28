chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scanUrl") {
        fetch("http://127.0.0.1:8000/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url })
        })
        .then(response => response.json())
        .then(data => sendResponse({ success: true, data: data }))
        .catch(err => sendResponse({ success: false, error: err.toString() }));
        
        // Returning true tells Chrome we will send the response asynchronously
        return true; 
    }
});