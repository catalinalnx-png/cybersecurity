import pandas as pd
import streamlit as st

from analyzer import detect, explain_with_ai, parse_auth_log

st.set_page_config(page_title="LogGuard AI", page_icon="🛡️", layout="wide")
st.title("🛡️ LogGuard AI")
st.caption("Regulile găsesc anomaliile, AI-ul le explică. Logul brut nu este trimis niciodată către AI.")

with st.sidebar:
    st.header("Setări")
    brute = st.slider("Prag brute force (eșecuri / 10 min)", 3, 50, 10)
    enum = st.slider("Prag enumerare username-uri", 2, 20, 5)
    use_ai = st.checkbox("Explicații AI (Claude)", value=True)
    api_key = st.text_input("Anthropic API key", type="password") if use_ai else None
    mask = st.checkbox("Maschează IP-urile înainte de AI", value=True)

up = st.file_uploader("Încarcă auth.log", type=["log", "txt"])
if up is None and st.button("Folosește logul de exemplu"):
    up = open("sample_auth.log", "rb")

if up:
    text = up.read().decode("utf-8", errors="ignore")
    df = parse_auth_log(text)
    if df.empty:
        st.error("Nu am găsit evenimente SSH recunoscute în fișier.")
        st.stop()

    anomalies = detect(df, brute_threshold=brute, enum_threshold=enum)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Evenimente", len(df))
    c2.metric("Login-uri eșuate", int((df.event == "failed").sum()))
    c3.metric("Login-uri reușite", int((df.event == "accepted").sum()))
    c4.metric("Anomalii", len(anomalies))

    st.subheader("Eșecuri în timp")
    fails = df[df.event == "failed"].set_index("time").resample("10min").size()
    st.bar_chart(fails)

    st.subheader("Top IP-uri suspecte")
    top = df[df.event == "failed"].groupby("ip").size().sort_values(ascending=False).head(10)
    st.dataframe(top.rename("eșecuri"), use_container_width=True)

    ai = None
    if use_ai and anomalies:
        with st.spinner("Claude analizează anomaliile..."):
            try:
                ai = explain_with_ai(anomalies, api_key=api_key or None, mask=mask)
            except Exception as e:
                st.warning(f"Analiza AI a eșuat ({e}). Afișez doar rezultatele din reguli.")

    if ai:
        st.subheader(f"Rezumat AI — risc general: {ai.get('overall_risk', '?').upper()}")
        st.info(ai.get("summary", ""))
    by_id = {f["id"]: f for f in (ai or {}).get("findings", [])}

    st.subheader("Anomalii detectate")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i, a in sorted(enumerate(anomalies), key=lambda x: order[x[1]["severity_hint"]]):
        f = by_id.get(i, {})
        sev = f.get("severity", a["severity_hint"])
        with st.expander(f"[{sev.upper()}] {a['title']}"):
            if f:
                st.markdown(f"**Explicație:** {f['explanation']}")
                if f.get("likely_false_positive"):
                    st.caption("⚠️ AI-ul consideră că ar putea fi fals pozitiv.")
                st.markdown("**Pași recomandați:**\n" + "\n".join(f"- {x}" for x in f["actions"]))
            st.markdown(f"**Regulă:** `{a['rule']}` · {a['first_seen']} → {a['last_seen']}")
            st.markdown("**Dovezi (linii originale):**")
            st.code("\n".join(a["evidence"]), language="text")