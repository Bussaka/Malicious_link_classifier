"""End-to-end test of the ThreatScanner extension in a real browser, driven over the DevTools protocol.

    uvicorn api:app --port 8000          # in one terminal, with url_classifier_v4.joblib built
    python tests/e2e/run_e2e.py          # in another

Covers: a phishing page is blocked, a malicious iframe gets the compact notice, hovering then
clicking a flagged link shows the warning, a malicious download is cancelled, an in-page
(pushState) navigation is rescanned, and the options page connects to the API.

Requirements:
* Microsoft Edge (or Chromium / Chrome for Testing via BROWSER=...). Branded Chrome 137+ ignores
  --load-extension, so it can't be used here.
* Port 80 free on 127.0.0.1: the test site is served as *.localtest.me, a public wildcard
  domain that resolves to 127.0.0.1. Hostnames with an IP or a port in them score as
  malicious on their own, so they couldn't stand in for a benign site.
* pip install websockets
Screenshots go to tests/e2e/output/.
"""
import asyncio, base64, functools, http.server, json, os, subprocess, sys, tempfile, threading, time, urllib.request
import websockets

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXT = os.path.join(ROOT, "ThreatScanner_Extension")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
CHROME = os.environ.get("BROWSER", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
PORT = 9335
results = []

FAKE_PAGE = "<!doctype html><html><head><title>Fake page</title></head><body><h1>Fake sign-in page</h1><form><input placeholder=password></form></body></html>"
SITE = {
    "index.html": """<!doctype html><html><head><meta charset="utf-8"><title>Test blog</title>
<style>body{font:15px system-ui;margin:40px;color:#222} a{display:inline-block;margin:8px 0;font-size:18px}</style></head>
<body><h1 id="title">My test blog</h1>
<p>A normal page with a suspicious link, a suspicious embedded frame and a download link.</p>
<p><a id="bad-link" href="http://paypal.com.account-verify.localtest.me/login">Verify your PayPal account</a></p>
<p><a id="good-link" href="http://myblog.localtest.me/spa.html">Another post on this blog</a></p>
<iframe id="frame" src="http://paypal-secure-login.localtest.me/webapps/auth/verify/" width="460" height="130" style="border:1px solid #ccc"></iframe>
</body></html>""",
    "spa.html": """<!doctype html><html><head><meta charset="utf-8"><title>SPA</title></head>
<body><h1>Single-page app</h1><p id="route">home</p></body></html>""",
    "login/index.html": FAKE_PAGE,
    "webapps/auth/verify/index.html": FAKE_PAGE,
    "app/settings/index.html": FAKE_PAGE,
    "bins/setup.exe": "MZ fake executable payload " * 150,
}


def serve_site():
    root = tempfile.mkdtemp(prefix="ts-site-")
    for path, content in SITE.items():
        full = os.path.join(root, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    class QuietServer(http.server.ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            pass   # the browser drops keep-alive connections when it's killed at the end

    server = QuietServer(("127.0.0.1", 80), functools.partial(QuietHandler, directory=root))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)


class CDP:
    def __init__(self, ws):
        self.ws, self.next_id, self.events = ws, 0, []

    async def call(self, method, **params):
        self.next_id += 1
        my_id = self.next_id
        await self.ws.send(json.dumps({"id": my_id, "method": method, "params": params}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == my_id:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
            if "method" in msg:
                self.events.append(msg)

    async def eval(self, expr, context_id=None, await_promise=False):
        params = dict(expression=expr, returnByValue=True, awaitPromise=await_promise)
        if context_id:
            params["contextId"] = context_id
        r = await self.call("Runtime.evaluate", **params)
        return r.get("result", {}).get("value")

    async def drain(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                msg = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=max(0.05, end - time.time())))
                if "method" in msg:
                    self.events.append(msg)
            except asyncio.TimeoutError:
                break


def targets():
    return json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json"))


async def screenshot(page, name, width=1100, height=800):
    await page.call("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=False)
    shot = await page.call("Page.captureScreenshot", format="png")
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(base64.b64decode(shot["data"]))


async def wait_for_block(page, timeout=10.0):
    """Polls until the block page appears. Returns (blocked, seconds, still_hidden) so a slow scan
    (page hidden, verdict pending) is distinguishable from no scan at all."""
    start = time.time()
    while time.time() - start < timeout:
        if await page.eval("document.title") == "Page blocked | ThreatScanner":
            return True, time.time() - start, False
        await page.drain(0.25)
    hidden = await page.eval("getComputedStyle(document.documentElement).visibility") == "hidden"
    return False, time.time() - start, hidden


async def navigate(page, url, settle=3.0):
    await page.call("Page.navigate", url=url)
    await page.drain(settle)


async def main():
    for _ in range(100):
        try:
            ts = targets()
            if any(t["type"] == "service_worker" and t["url"].endswith("/background.js") for t in ts) and any(t["type"] == "page" for t in ts):
                break
        except Exception:
            pass
        time.sleep(0.2)
    sw_target = next(t for t in targets() if t["type"] == "service_worker" and t["url"].endswith("/background.js"))
    ext_id = sw_target["url"].split("/")[2]
    page_target = next(t for t in targets() if t["type"] == "page")
    version = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/version"))

    async with websockets.connect(sw_target["webSocketDebuggerUrl"], max_size=None) as sw_ws, \
               websockets.connect(page_target["webSocketDebuggerUrl"], max_size=None) as page_ws, \
               websockets.connect(version["webSocketDebuggerUrl"], max_size=None) as browser_ws:
        sw, page, browser = CDP(sw_ws), CDP(page_ws), CDP(browser_ws)
        await page.call("Page.enable")
        await page.call("Runtime.enable")
        await sw.call("Runtime.enable")
        # A freshly loaded extension registers its content scripts a moment after its worker
        # starts; without a warm-up the very first navigation can slip past
        await page.drain(2)
        await navigate(page, "http://myblog.localtest.me/spa.html", settle=2)

        # Extension is loaded and the health check reached the API
        status = await sw.eval("checkHealth().then(s => s)", await_promise=True)
        check("service worker health check reaches the API", bool(status and status.get("online")), str(status))

        # 1. A phishing-style page is blocked
        await navigate(page, "http://paypal.com.account-verify.localtest.me/login/", settle=0.5)
        blocked, waited, hidden = await wait_for_block(page)
        title = f"blocked after {waited:.1f}s" if blocked else f"not blocked after {waited:.0f}s (page {'still hidden' if hidden else 'visible'})"
        if not blocked:
            print("   storage:", await sw.eval("chrome.storage.local.get(null).then(x => JSON.stringify(Object.keys(x)))", await_promise=True))
            contexts = [e["params"]["context"].get("name") for e in page.events if e.get("method") == "Runtime.executionContextCreated"]
            print("   page contexts:", contexts)
            for e in page.events + sw.events:
                if e.get("method") in ("Runtime.consoleAPICalled", "Runtime.exceptionThrown"):
                    print("   ", json.dumps(e["params"])[:300])
        check("phishing page replaced by block page", blocked, title)
        chart = False
        for _ in range(20):
            chart = await page.eval("!!document.querySelector('#ts-why .ts-row')")
            if chart:
                break
            await page.drain(0.25)
        check("explanation chart fills in on the block page", chart)
        await screenshot(page, "e2e_block.png")

        # 2. Benign page loads; its malicious iframe gets the compact notice
        await navigate(page, "http://myblog.localtest.me/index.html", settle=4)
        visible = await page.eval("getComputedStyle(document.documentElement).visibility + '|' + document.title")
        check("benign page is shown", visible == "visible|Test blog", visible)
        tree = await page.call("Page.getFrameTree")
        child_frames = tree["frameTree"].get("childFrames", [])
        frame_text = None
        if child_frames:
            world = await page.call("Page.createIsolatedWorld", frameId=child_frames[0]["frame"]["id"])
            frame_text = await page.eval("document.body && document.body.innerText", context_id=world["executionContextId"])
        check("malicious iframe shows the compact block notice",
              bool(frame_text and "Embedded content blocked" in frame_text), repr(frame_text)[:120])
        await screenshot(page, "e2e_iframe.png")

        # 3. Hover a malicious link, then click: warning dialog, navigation prevented
        rect = await page.eval("JSON.stringify(document.getElementById('bad-link').getBoundingClientRect())")
        r = json.loads(rect)
        x, y = r["x"] + r["width"] / 2, r["y"] + r["height"] / 2
        await page.call("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y)
        await page.drain(1.5)   # hover delay + scan
        await page.call("Input.dispatchMouseEvent", type="mousePressed", x=x, y=y, button="left", clickCount=1)
        await page.call("Input.dispatchMouseEvent", type="mouseReleased", x=x, y=y, button="left", clickCount=1)
        await page.drain(1.0)
        still_here = await page.eval("location.href")
        dialog = await page.eval("[...document.documentElement.children].some(e => e.tagName === 'DIV' && !e.id && e.shadowRoot === null && getComputedStyle(e).display !== 'none')")
        check("click on flagged link is held on the page", still_here == "http://myblog.localtest.me/index.html", still_here)
        check("warning dialog host is attached", bool(dialog))
        await screenshot(page, "e2e_link_warning.png")

        # Dismiss with Escape
        await page.call("Input.dispatchKeyEvent", type="keyDown", key="Escape", code="Escape", windowsVirtualKeyCode=27)
        await page.call("Input.dispatchKeyEvent", type="keyUp", key="Escape", code="Escape", windowsVirtualKeyCode=27)
        await page.drain(0.5)
        dialog_after = await page.eval("[...document.documentElement.children].some(e => e.tagName === 'DIV' && !e.id && e.shadowRoot === null)")
        check("Escape closes the warning dialog", not dialog_after)

        # 4. A malicious download started without hovering (no link precheck) is cancelled
        await browser.call("Browser.setDownloadBehavior", behavior="default", eventsEnabled=True)
        await page.eval("""(() => { const a = document.createElement('a');
            a.href = 'http://update-security-microsoft.localtest.me/bins/setup.exe'; document.body.appendChild(a); a.click(); })()""")
        await browser.drain(4)
        states = [e["params"].get("state") for e in browser.events if e.get("method") == "Browser.downloadProgress"]
        files = os.listdir(DL_DIR)
        check("malicious download is cancelled", "canceled" in states and not any(f.endswith(".exe") for f in files),
              f"states={sorted(set(states))} files={files}")

        # 5. SPA: in-page navigation is rescanned (host verdict expired to force a scan)
        await navigate(page, "http://myblog.localtest.me/spa.html", settle=3)
        await sw.eval("chrome.storage.local.remove('safe:myblog.localtest.me')", await_promise=True)
        await page.eval("history.pushState({}, '', '/app/settings'); document.getElementById('route').textContent = 'settings'")
        blocked, waited, _ = await wait_for_block(page)
        if not blocked:
            print("   storage:", await sw.eval("chrome.storage.local.get(null).then(x => JSON.stringify(Object.keys(x)))", await_promise=True))
            print("   location:", await page.eval("location.href"))
            for e in page.events + sw.events:
                if e.get("method") in ("Runtime.consoleAPICalled", "Runtime.exceptionThrown"):
                    print("   ", json.dumps(e["params"])[:300])
        check("pushState navigation to a flagged route is rescanned and blocked", blocked,
              f"after {waited:.1f}s")

        # 6. Options page renders with defaults
        await navigate(page, f"chrome-extension://{ext_id}/options.html", settle=2)
        api_value = await page.eval("document.getElementById('api-url').value")
        check("options page shows the API address", api_value == "http://127.0.0.1:8000", repr(api_value))
        await page.eval("document.getElementById('test').click()")
        await page.drain(2)
        msg = await page.eval("document.getElementById('api-message').textContent")
        check("options 'Test connection' succeeds", bool(msg and msg.startswith("Connected")), repr(msg))
        await screenshot(page, "e2e_options.png", height=980)


DL_DIR = tempfile.mkdtemp(prefix="ts-dl-")

if __name__ == '__main__':
    try:
        urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=3)
    except Exception:
        sys.exit("The API isn't running on :8000 - start it with: uvicorn api:app --port 8000")
    os.makedirs(OUT, exist_ok=True)
    site = serve_site()

    profile = tempfile.mkdtemp(prefix="ts-e2e-")
    os.makedirs(os.path.join(profile, "Default"))
    # Downloads go through the browser's normal path (so extension hooks apply) into a temp folder
    with open(os.path.join(profile, "Default", "Preferences"), "w") as f:
        json.dump({"download": {"default_directory": DL_DIR, "prompt_for_download": False}}, f)
    proc = subprocess.Popen([CHROME, "--headless=new", f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}",
                             f"--load-extension={EXT}", f"--disable-extensions-except={EXT}",
                             "--no-first-run", "--no-default-browser-check", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        asyncio.run(asyncio.wait_for(main(), timeout=150))
    except Exception as e:
        print("ERROR", type(e).__name__, e)
    finally:
        proc.kill()
        site.shutdown()
    passed = sum(ok for _, ok in results)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if results and passed == len(results) else 1)
