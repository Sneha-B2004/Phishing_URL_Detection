import streamlit as st
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import joblib
import numpy as np
import pandas as pd
from feature_engineering.feature_extraction import extract_features

st.set_page_config(
    page_title="AI Phishing URL Detector",
    page_icon="🔐",
    layout="wide"
)

# Hero Title Section
st.markdown("""
<div style='text-align:center;padding:40px'>
<h1>🔐 Phishing URL Detection</h1>
<p style='font-size:22px'>
Machine Learning Security System for Detecting Malicious Websites
</p>
</div>
""", unsafe_allow_html=True)

# CSS Styling
st.markdown("""
<style>

/* Background */
.stApp {
    background: linear-gradient(rgba(5,10,25,0.85), rgba(5,10,25,0.95)),
    url("assets/phishing_bg.png");
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}

/* Container box */
.block-container {
    background: rgba(0,0,0,0.35);
    padding: 2rem;
    border-radius: 15px;
}

/* Main title */
h1 {
    color: #00eaff !important;
    text-align: center !important;
    font-size: 48px !important;
    font-weight: 900 !important;
}

/* Section headings */
h2 {
    color: #ffffff !important;
    font-size: 36px !important;
    font-weight: 900 !important;
}

/* Sub headings */
h3 {
    color: #e6faff !important;
    font-size: 28px !important;
    font-weight: 800 !important;
}

/* Text */
p,label {
    color: #e6faff;
}

/* Buttons */
.stButton>button {
    background: linear-gradient(90deg,#00eaff,#00aaff);
    color: black;
    border-radius: 8px;
    font-weight: bold;
    padding: 10px 20px;
}

/* Text input */
.stTextInput input {
    border: 2px solid #00eaff;
    border-radius: 8px;
}

/* File uploader */
.stFileUploader {
    border: 2px dashed #00eaff;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

# Load model
model = joblib.load("models/phishing_model.pkl")

st.markdown("""
### About the Project

Phishing attacks are one of the most common cyber threats on the internet. 
Attackers create fake websites that mimic legitimate platforms in order to 
steal sensitive information such as login credentials, banking details, 
and personal data.

This project presents a **Machine Learning based Phishing URL Detection System** 
that automatically analyzes URLs and determines whether they are **legitimate, 
suspicious, or phishing**. The system extracts several important URL features 
such as domain structure, special characters, URL length, HTTPS usage, and 
other behavioral indicators that are commonly associated with phishing attacks.

A trained machine learning model processes these features and calculates 
a **phishing risk score** that helps users understand the likelihood of a URL 
being malicious.

The application provides two main functionalities:

• **Single URL Analysis** – Allows users to manually enter a URL and instantly receive a phishing risk assessment.  

• **Bulk URL Scanning** – Enables security analysts or researchers to upload a CSV file containing multiple URLs and perform automated phishing detection for all entries.

By combining **feature engineering, machine learning classification models, 
and an interactive Streamlit interface**, this system provides a simple yet 
powerful tool for identifying potentially harmful websites and promoting 
safer browsing practices.
""")


st.divider()
# ================= ELITE: BULK URL SCANNER =================
#st.header("📂 Bulk URL Scanner")
st.markdown("## 📂 BULK URL SCANNER")
st.write("Upload a CSV file containing URLs to scan multiple websites at once.")

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
            if phishing_prob >= 0.45:
                result = "Phishing"
            elif phishing_prob >= 0.30:
                result = "Suspicious"
            else:
                result = "Legitimate"

            results.append(result)

        df["Prediction"] = results

        st.write("### 🔎 Scan Results")
        st.dataframe(df)
        csv = df.to_csv(index=False).encode('utf-8')

        st.download_button(
        "⬇ Download Scan Results",
        csv,
        "scan_results.csv",
        "text/csv"
        )

    else:
        st.error("CSV must contain a column named 'url'")

# ===========================================================

# ================= SINGLE URL SCANNER =================
#st.header("🔗 Single URL Scanner")
st.markdown("## 🔗 SINGLE URL SCANNER")
st.write("Enter a website URL below to analyze if it is phishing or legitimate.")

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
        risk_score = int(phishing_prob * 100)

        st.progress(risk_score)

        st.metric("Phishing Risk Score", f"{risk_score}%")

        # Decision
        if phishing_prob >= 0.55:
            st.error("🚨 High Risk: Phishing Website")
        elif 0.30 <= phishing_prob < 0.45:
            st.warning("⚠️ Suspicious Website (Be Careful)")
        else:
            st.success("✅ Likely Legitimate Website")

    else:
        st.warning("Please enter a URL")
