import streamlit as st
import joblib
import numpy as np
import pandas as pd
from feature_extraction import extract_features

# Load model
model = joblib.load("models/phishing_model.pkl")

st.title("🔐 Real-Time Phishing URL Detector")

# ================= ELITE: BULK URL SCANNER =================
st.subheader("📂 Bulk URL Scanner")

uploaded_file = st.file_uploader(
    "Upload CSV file (must contain column named 'url')",
    type=["csv"]
)

if uploaded_file is not None:

    df = pd.read_csv(uploaded_file)

    if "url" in df.columns:

        results = []

        for url_item in df["url"]:

            features = extract_features(url_item)
            input_data = np.array(features).reshape(1, -1)

            prediction_proba = model.predict_proba(input_data)[0]
            phishing_prob = prediction_proba[0]
            legit_prob = prediction_proba[1]

            # ===== Boosting Logic =====
            suspicious_keywords = [
                "login", "verify", "update",
                "secure", "account", "bank", "paypal"
            ]

            if any(word in url_item.lower() for word in suspicious_keywords):
                phishing_prob += 0.25

            trusted_brands = [
                "google", "paypal",
                "amazon", "bank", "microsoft"
            ]

            if any(brand in url_item.lower() for brand in trusted_brands) and "-" in url_item:
                phishing_prob += 0.30

            # Normalize
            total = phishing_prob + legit_prob
            phishing_prob = phishing_prob / total

            # Decision
            if phishing_prob >= 0.55:
                result = "Phishing"
            elif phishing_prob >= 0.40:
                result = "Suspicious"
            else:
                result = "Legitimate"

            results.append(result)

        df["Prediction"] = results

        st.write("### 🔎 Scan Results")
        st.dataframe(df)

    else:
        st.error("CSV must contain a column named 'url'")

# ===========================================================

# ================= SINGLE URL SCANNER =================
st.subheader("🔗 Single URL Scanner")

url = st.text_input("Enter Website URL")

if st.button("Check URL"):

    if url:

        features = extract_features(url)
        input_data = np.array(features).reshape(1, -1)

        prediction_proba = model.predict_proba(input_data)[0]

        phishing_prob = prediction_proba[0]
        legit_prob = prediction_proba[1]

        # ===== Boosting Logic =====
        suspicious_keywords = [
            "login", "verify", "update",
            "secure", "account", "bank", "paypal"
        ]

        if any(word in url.lower() for word in suspicious_keywords):
            phishing_prob += 0.25

        trusted_brands = [
            "google", "paypal",
            "amazon", "bank", "microsoft"
        ]

        if any(brand in url.lower() for brand in trusted_brands) and "-" in url:
            phishing_prob += 0.30

        # Normalize
        total = phishing_prob + legit_prob
        phishing_prob = phishing_prob / total
        legit_prob = legit_prob / total

        # Show probabilities
        st.write(f"Phishing Probability: {round(phishing_prob*100,2)}%")
        st.write(f"Legitimate Probability: {round(legit_prob*100,2)}%")

        # ================= ADVANCED: EXPLANATION ENGINE =================
        reasons = []

        if any(word in url.lower() for word in suspicious_keywords):
            reasons.append("Suspicious keyword detected in URL")

        if any(brand in url.lower() for brand in trusted_brands) and "-" in url:
            reasons.append("Possible brand impersonation (hyphen used with trusted brand name)")

        if not url.startswith("https"):
            reasons.append("Website does not use HTTPS")

        if len(url) > 75:
            reasons.append("Unusually long URL length")

        if reasons:
            st.subheader("🔎 Why this URL was flagged:")
            for reason in reasons:
                st.write("•", reason)

        # ===============================================================

        # Risk Meter
        st.subheader("📊 Risk Score")
        st.progress(int(phishing_prob * 100))

        # Decision
        if phishing_prob >= 0.55:
            st.error("🚨 High Risk: Phishing Website")
        elif 0.40 <= phishing_prob < 0.55:
            st.warning("⚠️ Suspicious Website (Be Careful)")
        else:
            st.success("✅ Likely Legitimate Website")

    else:
        st.warning("Please enter a URL")