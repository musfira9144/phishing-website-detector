# app.py
import streamlit as st
st.set_page_config(page_title="Phishing Website Detector", page_icon="🛡️", layout="centered")

import joblib, time, re, warnings, requests, urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
import plotly.graph_objects as go

# suppress insecure request warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------- Load artifacts -----------------
@st.cache_resource
def load_artifacts():
    model = joblib.load("extra_trees_model.pkl")
    features = joblib.load("features.pkl")
    try:
        scaler = joblib.load("scaler.pkl")
    except Exception:
        scaler = None
    return model, features, scaler

MODEL, FEATURES, SCALER = load_artifacts()

# ----------------- Feature extraction helpers -----------------
SUSPICIOUS_WORDS = set([
    "login","verify","update","confirm","secure","account","bank","pay","signin","submit",
    "password","admin","redirect","paypal","invoice","free","gift","prize"
])

def safe_get(url, timeout=5):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        return requests.get(url, headers=headers, timeout=timeout, verify=False)
    except Exception:
        return None

def is_ip(host):
    return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or "") else 0

def compute_features_from_url(url):
    vals = {f: 0 for f in FEATURES}
    for c in FEATURES:
        if "Pct" in c or c.endswith("RT"):
            vals[c] = 0.0

    u = str(url).strip()
    if u == "":
        return vals
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u

    parsed = urlparse(u)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = u

    # Lexical features
    if 'NumDots' in vals: vals['NumDots'] = host.count('.') if host else 0
    if 'SubdomainLevel' in vals: vals['SubdomainLevel'] = max(0, len([p for p in host.split('.') if p]) - 2) if host else 0
    if 'PathLevel' in vals: vals['PathLevel'] = path.count('/') if path else 0
    if 'UrlLength' in vals: vals['UrlLength'] = len(full)
    if 'NumDash' in vals: vals['NumDash'] = full.count('-')
    if 'NumDashInHostname' in vals: vals['NumDashInHostname'] = host.count('-') if host else 0
    if 'AtSymbol' in vals: vals['AtSymbol'] = 1 if '@' in full else 0
    if 'TildeSymbol' in vals: vals['TildeSymbol'] = 1 if '~' in full else 0
    if 'NumUnderscore' in vals: vals['NumUnderscore'] = full.count('_')
    if 'NumPercent' in vals: vals['NumPercent'] = full.count('%')
    if 'NumQueryComponents' in vals: vals['NumQueryComponents'] = len(query.split('&')) if query else 0
    if 'NumAmpersand' in vals: vals['NumAmpersand'] = full.count('&')
    if 'NumHash' in vals: vals['NumHash'] = full.count('#')
    if 'NumNumericChars' in vals: vals['NumNumericChars'] = len(re.findall(r'\d', full))
    if 'NoHttps' in vals: vals['NoHttps'] = 1 if parsed.scheme != 'https' else 0
    if 'IpAddress' in vals: vals['IpAddress'] = is_ip(host)
    if 'HostnameLength' in vals: vals['HostnameLength'] = len(host)
    if 'PathLength' in vals: vals['PathLength'] = len(path)
    if 'QueryLength' in vals: vals['QueryLength'] = len(query)
    if 'DoubleSlashInPath' in vals: vals['DoubleSlashInPath'] = 1 if '//' in path else 0
    if 'NumSensitiveWords' in vals: vals['NumSensitiveWords'] = sum(1 for w in SUSPICIOUS_WORDS if w in full.lower())

    try:
        parts = host.split('.')
        if 'DomainInSubdomains' in vals:
            vals['DomainInSubdomains'] = 1 if (len(parts) >= 3 and parts[-2] in ".".join(parts[:-2])) else 0
        if 'DomainInPaths' in vals:
            vals['DomainInPaths'] = 1 if (len(parts) > 1 and parts[-2] in path) else 0
    except:
        pass
    if 'HttpsInHostname' in vals: vals['HttpsInHostname'] = 1 if 'https' in host else 0

    r = safe_get(full, timeout=6)
    if r and getattr(r, "status_code", 500) < 400:
        try:
            soup = BeautifulSoup(r.text, "lxml")
            anchors = [a.get('href','') for a in soup.find_all('a', href=True)]
            total_links = len(anchors)
            ext_links = 0
            for h in anchors:
                try:
                    hp = urlparse(h if re.match(r'^https?://', h, re.I) else parsed.scheme + '://' + host + (h if h.startswith('/') else '/' + h))
                    if hp.hostname and host and hp.hostname.lower() != host.lower():
                        ext_links += 1
                except:
                    pass
            if 'PctExtHyperlinks' in vals: vals['PctExtHyperlinks'] = (ext_links/total_links) if total_links>0 else 0.0

            if 'MissingTitle' in vals:
                vals['MissingTitle'] = 0 if soup.find('title') and soup.find('title').get_text().strip() else 1

        except Exception:
            if 'MissingTitle' in vals: vals['MissingTitle'] = 1
    else:
        if 'MissingTitle' in vals: vals['MissingTitle'] = 1

    if 'SubdomainLevelRT' in vals:
        vals['SubdomainLevelRT'] = 1 if vals.get('SubdomainLevel',0) >= 3 else (0 if vals.get('SubdomainLevel',0) == 2 else -1)
    if 'UrlLengthRT' in vals:
        vals['UrlLengthRT'] = 1 if vals.get('UrlLength',0) > 100 else (-1 if vals.get('UrlLength',0) < 40 else 0)

    return {f: vals.get(f, 0) for f in FEATURES}

# ----------------- Styling -----------------
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #e6edf3; }
    .hero { text-align: center; padding: 28px 8px; }
    .hero h1 { font-size: 42px; font-weight: 800; color: #58a6ff; margin-bottom: 5px; }
    .hero p { font-size: 16px; color: #c9d1d9; margin-top: 0; }
    .stTextInput>div>div>input {
        font-size:16px; padding:12px; border-radius:10px;
        border:2px solid #58a6ff; background:#161b22; color:#e6edf3;
        box-shadow: 0 0 6px #58a6ff;
    }
    .stTextInput>div>div>input::placeholder { color:#8b949e; opacity:0.8; font-style:italic; }
    .stButton>button {
        background: linear-gradient(90deg, #667eea, #764ba2);
        color:white; font-size:16px; border-radius:8px;
        padding:10px 22px; border:none; transition:0.22s;
    }
    .stButton>button:hover { transform: scale(1.06); box-shadow:0 0 8px #764ba2; }
    .result { margin: 18px auto; width: 60%; max-width: 480px; font-size:18px; font-weight:700;
              text-align:center; padding:14px; border-radius:10px; }
    .safe { background:#238636; color:white; box-shadow:0 0 5px #2ea043; }
    .phish { background:#b62324; color:white; box-shadow:0 0 5px #f85149; }
    .sus { background:#9e6a03; color:white; box-shadow:0 0 5px #f0a500; }
    </style>
""", unsafe_allow_html=True)

# ----------------- Hero -----------------
st.markdown(
    """
    <div class='hero'>
        <h1>🛡️ Phishing Website Detector</h1>
        <p>Paste a website URL below and get an ML-based risk score and explanation</p>
    </div>
    """,
    unsafe_allow_html=True
)

# ----------------- Input -----------------
url_input = st.text_input("🌐 Enter Website URL", placeholder="https://example.com/login")

if "has_result" not in st.session_state:
    st.session_state.has_result = False
if "show_top" not in st.session_state:
    st.session_state.show_top = False

if st.button("🔎 Analyze"):
    if not url_input.strip():
        st.warning("Please paste a URL to analyze.")
    else:
        with st.spinner("🔍 Extracting features and running model..."):
            start = time.time()
            feats = compute_features_from_url(url_input)
            X_df = pd.DataFrame([feats], columns=FEATURES)
            proba = float(MODEL.predict_proba(X_df)[:,1][0])
            pred = int(MODEL.predict(X_df)[0])
            runtime = time.time() - start
            score = int(round(proba * 100))

            st.session_state.has_result = True
            st.session_state.feats = feats
            st.session_state.pred = pred
            st.session_state.proba = proba
            st.session_state.score = score
            st.session_state.runtime = runtime

# ----------------- Show results -----------------
if st.session_state.has_result:
    pred = st.session_state.pred
    score = st.session_state.score
    proba = st.session_state.proba
    feats = st.session_state.feats
    runtime = st.session_state.runtime

    if pred == 0:
        st.markdown("<div class='result safe'>✅ Legitimate Website</div>", unsafe_allow_html=True)
    elif pred == 1:
        st.markdown("<div class='result phish'>🚨 Phishing Website</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='result sus'>⚠️ Suspicious Website</div>", unsafe_allow_html=True)

    # --- Risk Score Title above gauge ---
    st.markdown("<h4 style='text-align:center; color:#e6edf3; margin-top:20px;'>Risk Score</h4>", unsafe_allow_html=True)

    # --- Gauge ---
    gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={'font': {'color': '#e6edf3'}},
        gauge={
            'axis': {'range': [0, 100], 'tickvals': [0, 50, 100], 'ticktext': ['Low', 'Medium', 'High']},
            'bar': {'color': "#764ba2"},
            'steps': [
                {'range': [0, 40], 'color': "green"},
                {'range': [40, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "red"}
            ],
        }
    ))
    gauge.update_layout(
        height=250,
        margin=dict(l=20, r=20, t=40, b=20),
        paper_bgcolor="#0d1117",
        font={'color': '#e6edf3'}
    )
    st.plotly_chart(gauge, use_container_width=False)

    # Description below gauge
    st.write(f"⏱ Runtime: {runtime:.2f}s — Confidence (prob): {proba:.3f}")

    # --- Only one toggle ---
    st.session_state.show_top = st.checkbox("📊 Show Top Features", value=st.session_state.show_top, key="cb_top")
    if st.session_state.show_top:
        importances = MODEL.feature_importances_
        feat_vals = np.array([feats[f] for f in FEATURES], dtype=float)
        scores = importances * np.abs(feat_vals)
        top_idx = np.argsort(scores)[::-1][:6]
        expl = []
        for i in top_idx:
            expl.append({
                "feature": FEATURES[i],
                "value": float(feat_vals[i]),
                "importance": float(importances[i])
            })
        st.subheader("Top Contributing Features")
        st.table(pd.DataFrame(expl))

# ----------------- Footer -----------------
st.markdown("""
<hr style='margin-top:28px; margin-bottom:10px; border-color:#222;'/>
<p style='text-align:center; color:#8b949e; font-size:13px;'>
📘 Phishing Website Detector — Built with <b>Extra Trees ML Model</b> • Dataset: <a style='color:#58a6ff;' href='https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning' target='_blank'>Kaggle Dataset</a><br>
Internship Project • Developed by <b>Musfira</b>
</p>
""", unsafe_allow_html=True)
