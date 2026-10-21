import html

import altair as alt
import pandas as pd
import requests
import streamlit as st

from features import extract_features, normalize_url

API_URL = "http://127.0.0.1:8000"

# Palette - white and blue, with red/green reserved for the verdict itself.
# The chart pair (blue = toward safe, red = toward malicious) passes the colorblind-safety checks on white.
INK = "#0f2747"
INK_SECONDARY = "#4a5d78"
BLUE = "#256abf"
CHART_SAFE = "#2a78d6"
CHART_MALICIOUS = "#e34948"

EXAMPLES = {
    "Wikipedia": "https://www.wikipedia.org/",
    "Personal blog": "https://blog.janedoe.dev/2026/03/notes-on-rust-lifetimes",
    "Brand look-alike": "http://paypal.com.account-verify.xyz/login",
    "Malware download": "http://192.168.13.7:8080/bins/mirai.arm",
    "Google Form": "https://docs.google.com/forms/d/e/1FAIpQLSf3kD8x/viewform",
}

# Human-readable names for the model's features
FEATURE_LABELS = {
    'url_length': 'URL length', 'domain_length': 'Domain length', 'path_length': 'Path length',
    'num_digits': 'Digit count', 'num_special_chars': 'Special characters', 'has_ip': 'IP address as host',
    'num_suspicious_words': 'Sensitive keywords', 'domain_entropy': 'Domain randomness',
    'tld_length': 'TLD length', 'is_suspicious_tld': 'High-risk TLD', 'num_encoded_chars': 'Encoded characters',
    'directory_depth': 'Directory depth', 'subdomain_count': 'Subdomain depth', 'query_length': 'Query length',
    'num_query_params': 'Query parameters', 'host_digit_ratio': 'Digits in host', 'num_host_hyphens': 'Hyphens in host',
    'has_port': 'Explicit port', 'has_at_in_host': 'Credentials in host', 'brand_in_host': 'Brand outside its domain',
    'brand_in_path': 'Brand name in path',
}

ICONS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "alert": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    "check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "info": '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
}


def icon(name, size=20):
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="st-"], .stMarkdown, button, input {{ font-family: 'Inter', system-ui, sans-serif; }}
#MainMenu, footer, [data-testid="stDeployButton"] {{ display: none; }}
.block-container {{ padding-top: 2.5rem; max-width: 780px; }}

.ts-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.25rem; }}
.ts-brand {{ display: flex; align-items: center; gap: 10px; color: {BLUE}; }}
.ts-brand-name {{ font-size: 1.35rem; font-weight: 700; color: {INK}; letter-spacing: -0.01em; }}
.ts-brand-name span {{ color: {BLUE}; }}
.ts-pill {{ display: inline-flex; align-items: center; gap: 6px; font-size: 0.78rem; font-weight: 500;
           padding: 4px 10px; border-radius: 999px; border: 1px solid #dce6f2; color: {INK_SECONDARY}; background: #fff; }}
.ts-pill .dot {{ width: 7px; height: 7px; border-radius: 50%; }}
.ts-lede {{ color: {INK_SECONDARY}; font-size: 0.98rem; margin: 0.35rem 0 1.25rem 0; }}

.ts-verdict {{ display: flex; gap: 16px; align-items: flex-start; padding: 20px 22px; border-radius: 12px;
              border: 1px solid; margin: 0.5rem 0 1rem 0; }}
.ts-verdict .badge {{ flex: none; width: 44px; height: 44px; border-radius: 50%; display: flex;
                     align-items: center; justify-content: center; }}
.ts-verdict h3 {{ margin: 0; padding: 0; font-size: 1.15rem; font-weight: 600; color: {INK}; }}
.ts-verdict p {{ margin: 4px 0 0 0; color: {INK_SECONDARY}; font-size: 0.92rem; line-height: 1.45; }}
.ts-verdict.malicious {{ background: #fdf3f3; border-color: #f3caca; }}
.ts-verdict.malicious .badge {{ background: #fbe1e1; color: #c23434; }}
.ts-verdict.safe {{ background: #f2f9f4; border-color: #cfe8d6; }}
.ts-verdict.safe .badge {{ background: #dcf1e2; color: #17803d; }}
.ts-verdict.info {{ background: #f4f8fd; border-color: #d3e1f3; }}
.ts-verdict.info .badge {{ background: #e1ecfa; color: {BLUE}; }}

.ts-url {{ font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 0.84rem; color: {INK};
          background: #f4f8fd; border: 1px solid #dce6f2; border-radius: 8px; padding: 10px 12px;
          word-break: break-all; margin-top: 12px; }}
.ts-label {{ font-size: 0.72rem; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase;
            color: #7b8aa1; margin: 0 0 6px 0; }}

.ts-meter {{ margin: 0.25rem 0 1.5rem 0; }}
.ts-meter-head {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px; }}
.ts-meter-score {{ font-size: 1.9rem; font-weight: 700; color: {INK}; letter-spacing: -0.02em; }}
.ts-meter-caption {{ color: {INK_SECONDARY}; font-size: 0.85rem; }}
.ts-track {{ position: relative; height: 10px; border-radius: 999px; background: #e8eef7; }}
.ts-fill {{ position: absolute; left: 0; top: 0; bottom: 0; border-radius: 999px; }}
.ts-tick {{ position: absolute; top: -5px; bottom: -5px; width: 2px; background: {INK}; border-radius: 1px; }}
.ts-tick-label {{ position: absolute; top: 16px; transform: translateX(-50%); font-size: 0.72rem;
                 color: {INK_SECONDARY}; white-space: nowrap; }}

.ts-signals {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin-top: 4px; }}
.ts-signal {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 12px;
             border: 1px solid #dce6f2; border-radius: 8px; background: #fff; font-size: 0.86rem; color: {INK}; }}
.ts-signal .state {{ font-size: 0.78rem; font-weight: 500; color: #7b8aa1; white-space: nowrap; }}
.ts-signal.on {{ border-color: #f3caca; background: #fdf6f6; }}
.ts-signal.on .state {{ color: #c23434; }}

.ts-section {{ font-size: 1.02rem; font-weight: 600; color: {INK}; margin: 1.6rem 0 0.15rem 0; }}
.ts-section-sub {{ color: {INK_SECONDARY}; font-size: 0.86rem; margin-bottom: 0.6rem; }}
.ts-footer {{ color: #7b8aa1; font-size: 0.78rem; margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #e8eef7; }}
</style>
"""


@st.cache_data(ttl=10, show_spinner=False)
def fetch_health():
    try:
        return requests.get(f"{API_URL}/health", timeout=1.5).json()
    except requests.exceptions.RequestException:
        return None


def pick_example():
    choice = st.session_state.get("example")
    if choice:
        st.session_state.url_input = EXAMPLES[choice]
        st.session_state.run_scan = True
        st.session_state.example = None


def render_header(health):
    if health:
        pill = (f'<span class="ts-pill"><span class="dot" style="background:#17803d"></span>'
                f'API online &middot; model {html.escape(str(health.get("model", "")))}</span>')
    else:
        pill = '<span class="ts-pill"><span class="dot" style="background:#c23434"></span>API offline</span>'
    st.markdown(f"""
        <div class="ts-header">
          <div class="ts-brand">{icon("shield", 28)}<div class="ts-brand-name">Threat<span>Scanner</span></div></div>
          {pill}
        </div>
        <div class="ts-lede">Check any link before you open it. The model reads only the address, so nothing is visited or downloaded.</div>
    """, unsafe_allow_html=True)


def render_verdict(data, url):
    reason = data.get("reason")
    if reason == "allowlisted":
        cls, ico, title = "safe", "check", "Trusted domain"
        body = "This domain is among the most visited sites on the web, so it is allowed without running the model."
    elif reason == "document_platform":
        cls, ico, title = "info", "info", "Document platform: not judged"
        body = ("Google Docs/Drive/Forms and SharePoint/OneDrive links look the same whether the document is "
                "genuine or a phishing form, so they are never blocked. Check the sender before entering any details.")
    elif data["status"] == "Malicious":
        cls, ico, title = "malicious", "alert", "Threat detected"
        body = "This address has the structure of phishing or malware links. The browser extension would block it."
    else:
        cls, ico, title = "safe", "check", "No threat detected"
        body = "Nothing about this address resembles known phishing or malware patterns."

    st.markdown(f"""
        <div class="ts-verdict {cls}">
          <div class="badge">{icon(ico, 22)}</div>
          <div style="min-width:0; flex:1">
            <h3>{title}</h3>
            <p>{body}</p>
            <div class="ts-url">{html.escape(url)}</div>
          </div>
        </div>
    """, unsafe_allow_html=True)


def render_meter(data):
    score = min(max(data.get("malicious_probability", 0.0), 0.0), 1.0)
    threshold = data.get("threshold", 0.5)
    fill = CHART_MALICIOUS if data["status"] == "Malicious" else CHART_SAFE
    st.markdown(f"""
        <div class="ts-meter">
          <div class="ts-meter-head">
            <div><div class="ts-label">Malicious score</div><div class="ts-meter-score">{score:.1%}</div></div>
            <div class="ts-meter-caption">Blocked above {threshold:.1%}</div>
          </div>
          <div class="ts-track">
            <div class="ts-fill" style="width:{score * 100:.1f}%; background:{fill}"></div>
            <div class="ts-tick" style="left:{threshold * 100:.1f}%"></div>
            <div class="ts-tick-label" style="left:{threshold * 100:.1f}%">threshold</div>
          </div>
        </div>
    """, unsafe_allow_html=True)


def render_signals(url):
    f = extract_features(url)
    # Raw indicators, flagged with simple rules for display only - the model weighs them jointly
    signals = [
        ("IP address as host", f['has_ip'] == 1, "Yes" if f['has_ip'] else "No"),
        ("Brand outside its domain", f['brand_in_host'] == 1, "Yes" if f['brand_in_host'] else "No"),
        ("Brand name in path", f['brand_in_path'] == 1, "Yes" if f['brand_in_path'] else "No"),
        ("High-risk TLD", f['is_suspicious_tld'] == 1, "Yes" if f['is_suspicious_tld'] else "No"),
        ("Sensitive keywords", f['num_suspicious_words'] > 0, str(f['num_suspicious_words'])),
        ("Subdomain depth", f['subdomain_count'] >= 3, str(f['subdomain_count'])),
        ("Explicit port", f['has_port'] == 1, "Yes" if f['has_port'] else "No"),
        ("Encoded characters", f['num_encoded_chars'] > 0, str(f['num_encoded_chars'])),
        ("Credentials in host", f['has_at_in_host'] == 1, "Yes" if f['has_at_in_host'] else "No"),
        ("Domain randomness", f['domain_entropy'] > 4.0, f"{f['domain_entropy']:.2f} bits"),
    ]
    cards = "".join(
        f'<div class="ts-signal{" on" if flagged else ""}"><span>{name}</span><span class="state">{value}</span></div>'
        for name, flagged, value in signals)
    st.markdown(f"""
        <div class="ts-section">URL signals</div>
        <div class="ts-section-sub">Indicators extracted from the address as scored:
          <span style="font-family:'JetBrains Mono',monospace">{html.escape(normalize_url(url))}</span></div>
        <div class="ts-signals">{cards}</div>
    """, unsafe_allow_html=True)


def pretty_name(name):
    if name.startswith('ngram '):
        return 'Text pattern ' + name[len('ngram '):]
    return FEATURE_LABELS.get(name, name.replace('_', ' ').capitalize())


def render_explanation(explanation):
    df = pd.DataFrame(list(explanation.items()), columns=['feature', 'impact'])
    df = df[df['impact'] != 0]
    if df.empty:
        return
    df['label'] = df['feature'].map(pretty_name)
    df['direction'] = df['impact'].map(lambda v: 'Toward malicious' if v > 0 else 'Toward safe')
    df = df.reindex(df['impact'].abs().sort_values(ascending=False).index).head(10)

    st.markdown("""
        <div class="ts-section">Why the model decided this</div>
        <div class="ts-section-sub">The ten largest contributions to the score. Features come from the URL's structure;
        text patterns are character sequences the language model weighs.</div>
    """, unsafe_allow_html=True)

    bars = alt.Chart(df).mark_bar(cornerRadiusEnd=4, height=16).encode(
        x=alt.X('impact:Q', title='Contribution to malicious score',
                axis=alt.Axis(format='+.2f', tickCount=5, grid=True, gridColor='#eef2f8', domain=False, tickColor='#dce6f2',
                              labelColor=INK_SECONDARY, titleColor=INK_SECONDARY, titleFontWeight=500)),
        y=alt.Y('label:N', sort=None, title=None,
                axis=alt.Axis(labelColor=INK, labelFontSize=12, labelLimit=220, domain=False, ticks=False)),
        color=alt.Color('direction:N', title=None,
                        scale=alt.Scale(domain=['Toward malicious', 'Toward safe'], range=[CHART_MALICIOUS, CHART_SAFE]),
                        legend=alt.Legend(orient='top', direction='horizontal', labelColor=INK, symbolType='square')),
        tooltip=[alt.Tooltip('label:N', title='Signal'), alt.Tooltip('direction:N', title='Pushes'),
                 alt.Tooltip('impact:Q', title='Contribution', format='+.4f')],
    )
    zero = alt.Chart(pd.DataFrame({'x': [0]})).mark_rule(color='#9aa8bd', strokeWidth=1).encode(x='x:Q')
    chart = (bars + zero).properties(height=34 * len(df) + 30).configure_view(stroke=None).configure(
        font='Inter').configure_axis(labelFont='Inter', titleFont='Inter')
    st.altair_chart(chart, use_container_width=True)

    with st.expander("View as table"):
        st.dataframe(df[['label', 'direction', 'impact']].rename(columns={
            'label': 'Signal', 'direction': 'Pushes', 'impact': 'Contribution'}),
            hide_index=True, use_container_width=True)


st.set_page_config(page_title="ThreatScanner", page_icon=":material/shield:", layout="centered")
st.markdown(CSS, unsafe_allow_html=True)

# A ?url=... link opens straight into its scan, so results can be shared
if "url" in st.query_params and "url_input" not in st.session_state:
    st.session_state.url_input = st.query_params["url"]
    st.session_state.run_scan = True

health = fetch_health()
render_header(health)

with st.form("scan", border=False):
    col_input, col_button = st.columns([5, 1], vertical_alignment="bottom")
    url_input = col_input.text_input("URL to analyze", key="url_input", label_visibility="collapsed",
                                     placeholder="Paste a link, e.g. https://example.com/login")
    submitted = col_button.form_submit_button("Analyze", type="primary", use_container_width=True)

st.pills("Try an example", list(EXAMPLES), key="example", on_change=pick_example)

if submitted or st.session_state.pop("run_scan", False):
    url = (st.session_state.get("url_input") or "").strip()
    if not url:
        st.warning("Enter a URL to analyze.", icon=":material/link:")
    else:
        try:
            with st.spinner("Analyzing the address..."):
                response = requests.post(f"{API_URL}/scan", json={"url": url}, timeout=10)
            if response.status_code != 200:
                st.error(f"The API rejected the request (HTTP {response.status_code}). Check the backend logs.",
                         icon=":material/error:")
            else:
                data = response.json()
                render_verdict(data, url)
                if data.get("reason") == "model":
                    render_meter(data)
                render_signals(url)
                if data.get("explanation"):
                    render_explanation(data["explanation"])
        except requests.exceptions.ConnectionError:
            st.error("Can't reach the API. Start it with `uvicorn api:app --port 8000` and try again.",
                     icon=":material/cloud_off:")
        except requests.exceptions.Timeout:
            st.error("The API took too long to respond. It may still be loading the model.",
                     icon=":material/schedule:")

if health:
    st.markdown(f"""
        <div class="ts-footer">Model {html.escape(str(health['model']))} ({html.escape(str(health['kind']))})
        &middot; blocking threshold {health['threshold']:.1%}
        &middot; {health['allowlist_size']:,} allowlisted domains</div>
    """, unsafe_allow_html=True)
