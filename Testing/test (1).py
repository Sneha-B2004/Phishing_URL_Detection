import sys
import re
import pandas as pd
import matplotlib.pyplot as plt

from typing import List, Optional, Tuple
from playwright.sync_api import sync_playwright

APP_URL = "https://phishingurldetection-i46jpr2np6abcr6reqskxn.streamlit.app/"
BENCHMARK_CSV = "benchmark.csv"


def save_artifacts(page, prefix: str):
    page.screenshot(path=f"{prefix}.png", full_page=True)
    with open(f"{prefix}.html", "w", encoding="utf-8") as f:
        f.write(page.content())
    print(f"Saved: {prefix}.png, {prefix}.html")


def load_test_cases(csv_path: str) -> List[Tuple[str, str]]:
    df = pd.read_csv(csv_path)

    required_cols = {"url", "expected_label"}
    if not required_cols.issubset(df.columns):
        raise ValueError("CSV must contain columns: url, expected_label")

    cases = []
    for _, row in df.iterrows():
        url = str(row["url"]).strip()
        label = normalize_expected_label(str(row["expected_label"]))
        if url:
            cases.append((url, label))
    return cases


def normalize_expected_label(label: str) -> str:
    s = (label or "").strip().upper()

    if s in {"LEGITIMATE", "LIKELY LEGITIMATE"}:
        return "LEGITIMATE"

    if s in {"PHISHING", "SUSPICIOUS"}:
        return "PHISHING"

    raise ValueError(f"Invalid expected label: {label!r}")


_UI_PHISHING_STRINGS = {
    "🚨 High Risk: Phishing Website",
}
_UI_SUSPICIOUS_STRINGS = {
    "⚠️ Suspicious Website (Be Careful)",
}
_UI_LEGIT_STRINGS = {
    "✅ Likely Legitimate Website",
}


def normalize_status_from_ui_text(raw_text: str) -> Optional[str]:
    s = (raw_text or "").strip()

    if s in _UI_PHISHING_STRINGS:
        return "PHISHING"

    if s in _UI_SUSPICIOUS_STRINGS:
        return "PHISHING"

    if s in _UI_LEGIT_STRINGS:
        return "LEGITIMATE"

    return None


def extract_risk_score_percent(text: str) -> Optional[int]:
    m = re.search(r"Phishing Probability:\s*([0-9]+(?:\.[0-9]+)?)\s*%", text, flags=re.IGNORECASE)
    if not m:
        return None

    val = float(m.group(1))
    val = max(0.0, min(100.0, val))
    return int(round(val))


def get_streamlit_frame(page):
    page.wait_for_selector('iframe[title="streamlitApp"]', timeout=180000)
    return page.frame_locator('iframe[title="streamlitApp"]')


def wait_for_ui_ready(frame):
    frame.get_by_text("Real-Time Phishing URL Detector", exact=False).first.wait_for(timeout=180000)
    frame.get_by_text("Single URL Scanner", exact=False).first.wait_for(timeout=180000)
    frame.locator("button:has-text('Check URL')").first.wait_for(state="visible", timeout=180000)


def locate_single_url_input(frame):
    frame.get_by_text("Single URL Scanner", exact=False).first.wait_for(timeout=180000)

    loc = frame.locator('[data-testid="stTextInput"] input')
    if loc.count() > 0:
        return loc.first

    loc = frame.locator('div[data-baseweb="input"] input')
    if loc.count() > 0:
        return loc.first

    label = frame.get_by_text("Enter Website URL", exact=False).first
    if label.count() > 0:
        cand = label.locator("xpath=following::input[1]")
        if cand.count() > 0:
            return cand.first

    loc = frame.locator("input")
    if loc.count() > 0:
        return loc.first

    return None


def read_prediction_status(page, frame, timeout_ms: int = 90000) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    step = 500
    waited = 0
    last_risk = None

    while waited < timeout_ms:
        full_text = frame.locator("body").inner_text()

        risk = extract_risk_score_percent(full_text)
        if risk is not None:
            last_risk = risk

        matched_line = None
        for candidate in list(_UI_PHISHING_STRINGS | _UI_SUSPICIOUS_STRINGS | _UI_LEGIT_STRINGS):
            if candidate in full_text:
                matched_line = candidate
                break

        status = normalize_status_from_ui_text(matched_line) if matched_line else None
        if status in {"LEGITIMATE", "PHISHING"}:
            return status, last_risk, matched_line

        page.wait_for_timeout(step)
        waited += step

    return None, last_risk, None


def compute_metrics(results_df: pd.DataFrame):
    total = len(results_df)
    correct = int(results_df["is_correct"].sum())
    wrong = total - correct
    accuracy = (correct / total) * 100 if total else 0.0

    tp = int(((results_df["expected_label"] == "PHISHING") & (results_df["predicted_label"] == "PHISHING")).sum())
    tn = int(((results_df["expected_label"] == "LEGITIMATE") & (results_df["predicted_label"] == "LEGITIMATE")).sum())
    fp = int(((results_df["expected_label"] == "LEGITIMATE") & (results_df["predicted_label"] == "PHISHING")).sum())
    fn = int(((results_df["expected_label"] == "PHISHING") & (results_df["predicted_label"] == "LEGITIMATE")).sum())

    precision = tp / (tp + fp) * 100 if (tp + fp) else 0.0
    recall = tp / (tp + fn) * 100 if (tp + fn) else 0.0
    specificity = tn / (tn + fp) * 100 if (tn + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "total": total,
        "correct": correct,
        "wrong": wrong,
        "accuracy": accuracy,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
    }


def generate_professional_scorecard(metrics: dict, out_path: str = "scorecard.png"):
    fig = plt.figure(figsize=(14, 8))
    fig.patch.set_facecolor("white")

    fig.text(0.05, 0.94, "PhishGuard AI Security Evaluation Scorecard", fontsize=22, fontweight="bold")
    fig.text(0.05, 0.905, "Automated browser-driven benchmark on labeled URLs", fontsize=11)

    ax1 = fig.add_axes([0.05, 0.58, 0.28, 0.24])
    ax1.axis("off")
    ax1.text(0.5, 0.72, f"{metrics['accuracy']:.2f}%", ha="center", va="center", fontsize=30, fontweight="bold")
    ax1.text(0.5, 0.42, "Overall Accuracy", ha="center", va="center", fontsize=13)
    ax1.text(0.5, 0.18, f"{metrics['correct']} correct out of {metrics['total']}", ha="center", va="center", fontsize=11)
    ax1.add_patch(plt.Rectangle((0.02, 0.02), 0.96, 0.96, fill=False, linewidth=1.5, transform=ax1.transAxes))

    cards = [
        ("Precision", metrics["precision"]),
        ("Recall", metrics["recall"]),
        ("Specificity", metrics["specificity"]),
        ("F1 Score", metrics["f1"]),
    ]

    x_positions = [0.38, 0.53, 0.68, 0.83]
    for (label, value), x in zip(cards, x_positions):
        ax = fig.add_axes([x, 0.62, 0.11, 0.16])
        ax.axis("off")
        ax.text(0.5, 0.62, f"{value:.2f}%", ha="center", va="center", fontsize=18, fontweight="bold")
        ax.text(0.5, 0.25, label, ha="center", va="center", fontsize=11)
        ax.add_patch(plt.Rectangle((0.02, 0.02), 0.96, 0.96, fill=False, linewidth=1.2, transform=ax.transAxes))

    ax_cm = fig.add_axes([0.05, 0.14, 0.42, 0.30])
    ax_cm.axis("off")
    ax_cm.text(0.5, 1.05, "Confusion Matrix", ha="center", va="bottom", fontsize=16, fontweight="bold")

    cells = [
        ("TP", metrics["tp"], 0.00, 0.50),
        ("FP", metrics["fp"], 0.50, 0.50),
        ("FN", metrics["fn"], 0.00, 0.00),
        ("TN", metrics["tn"], 0.50, 0.00),
    ]
    for name, value, x, y in cells:
        ax_cm.add_patch(plt.Rectangle((x, y), 0.48, 0.48, fill=False, linewidth=1.5, transform=ax_cm.transAxes))
        ax_cm.text(x + 0.24, y + 0.30, name, ha="center", va="center", fontsize=14, fontweight="bold")
        ax_cm.text(x + 0.24, y + 0.15, str(value), ha="center", va="center", fontsize=20)

    ax_cm.text(0.24, 1.0, "Predicted: PHISHING", ha="center", va="bottom", fontsize=10)
    ax_cm.text(0.74, 1.0, "Predicted: LEGITIMATE", ha="center", va="bottom", fontsize=10)
    ax_cm.text(-0.08, 0.74, "Actual:\nPHISHING", ha="right", va="center", fontsize=10)
    ax_cm.text(-0.08, 0.24, "Actual:\nLEGITIMATE", ha="right", va="center", fontsize=10)

    ax_sum = fig.add_axes([0.55, 0.14, 0.38, 0.30])
    ax_sum.axis("off")
    ax_sum.text(0.0, 0.92, "Executive Summary", fontsize=16, fontweight="bold")
    summary_lines = [
        f"• Total URLs evaluated: {metrics['total']}",
        f"• Correct predictions: {metrics['correct']}",
        f"• Incorrect predictions: {metrics['wrong']}",
        f"• Phishing recall: {metrics['recall']:.2f}%",
        f"• Legitimate specificity: {metrics['specificity']:.2f}%",
        "• Suspicious outputs are mapped to PHISHING",
    ]
    y = 0.75
    for line in summary_lines:
        ax_sum.text(0.0, y, line, fontsize=12)
        y -= 0.12

    plt.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Professional scorecard saved as: {out_path} ✅")


def run_suite(test_cases: List[Tuple[str, str]], headless: bool = False):
    rows = []

    with sync_playwright() as p:
        print("🚀 Launching browser...")
        browser = p.chromium.launch(headless=headless, slow_mo=120)
        page = browser.new_page()

        # Increased waiting time
        page.set_default_timeout(180000)
        page.set_default_navigation_timeout(180000)

        try:
            print("🌐 Opening app wrapper...")
            page.goto(APP_URL, wait_until="load", timeout=180000)

            # Cold start delay for Streamlit Cloud
            print("⏳ Waiting for Streamlit cold start...")
            page.wait_for_timeout(15000)

            current_url = page.url.lower()
            if "errors/not_found" in current_url:
                raise RuntimeError("Streamlit app not found. The deployment URL is invalid, deleted, or renamed.")

            if "authkit.streamlit.io" in current_url or "accounts.google.com" in current_url:
                raise RuntimeError("Streamlit app is not publicly accessible. Set visibility to Public in Streamlit Cloud.")

            print("🧩 Switching into Streamlit iframe...")
            frame = get_streamlit_frame(page)

            print("⏳ Waiting for UI inside iframe...")
            wait_for_ui_ready(frame)

            print("🔎 Locating URL input...")
            url_input = locate_single_url_input(frame)
            if url_input is None:
                save_artifacts(page, "no_input_found")
                raise RuntimeError("Could not locate URL input. See no_input_found.png/html")

            check_btn = frame.locator("button:has-text('Check URL')").first

            total = len(test_cases)
            for i, (url, expected) in enumerate(test_cases, start=1):
                print(f"[{i}/{total}] Testing: {url} | Expected: {expected}")

                url_input.click(force=True)
                url_input.fill("")
                url_input.type(url, delay=10)
                check_btn.click(force=True)

                predicted, risk, banner = read_prediction_status(page, frame, timeout_ms=90000)

                row = {
                    "url": url,
                    "expected_label": expected,
                    "predicted_label": predicted if predicted else "NO_OUTPUT",
                    "risk_score": risk,
                    "banner": banner,
                }
                row["is_correct"] = row["expected_label"] == row["predicted_label"]
                rows.append(row)

                page.wait_for_timeout(500)

            browser.close()
            return pd.DataFrame(rows)

        except Exception as e:
            print(f"\n❌ Suite failed: {e}")
            save_artifacts(page, "suite_failure")
            browser.close()
            raise


def main():
    test_cases = load_test_cases(BENCHMARK_CSV)
    if len(test_cases) != 100:
        raise ValueError(f"Expected exactly 100 URLs in {BENCHMARK_CSV}, found {len(test_cases)}")

    results_df = run_suite(test_cases, headless=False)
    results_df.to_csv("detailed_results.csv", index=False)

    metrics = compute_metrics(results_df)

    print("\n=== Automated Correctness Report ===")
    print(f"Total tests: {metrics['total']}")
    print(f"Correct:     {metrics['correct']}")
    print(f"Wrong:       {metrics['wrong']}")
    print(f"Accuracy:    {metrics['accuracy']:.2f}%")
    print(f"Precision:   {metrics['precision']:.2f}%")
    print(f"Recall:      {metrics['recall']:.2f}%")
    print(f"Specificity: {metrics['specificity']:.2f}%")
    print(f"F1 Score:    {metrics['f1']:.2f}%")

    generate_professional_scorecard(metrics, out_path="scorecard.png")

    sys.exit(0 if metrics["wrong"] == 0 else 1)


if __name__ == "__main__":
    main()