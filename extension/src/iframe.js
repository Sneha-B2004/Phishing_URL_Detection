function setUrl(u) {
  const input = document.getElementById("url");
  if (input) input.value = u || "";
}

async function predict(url) {
  const res = await fetch("http://127.0.0.1:8000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

window.addEventListener("message", (event) => {
  if (event?.data?.type === "PHISHGUARD_URL") {
    setUrl(event.data.url);
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const result = document.getElementById("result");
  const score = document.getElementById("score");
  const btn = document.getElementById("check");
  const input = document.getElementById("url");

  btn.addEventListener("click", async () => {
    const url = (input.value || "").trim();

    if (!url) {
      result.textContent = "No URL found. Paste one.";
      score.textContent = "";
      return;
    }

    result.textContent = "Checking...";
    score.textContent = "";

    try {
      const data = await predict(url);
      result.textContent = data.status;
      score.textContent = `Risk Score: ${Number(data.risk_score).toFixed(3)}`;
    } catch (e) {
      result.textContent = "API error";
      score.textContent = String(e.message).slice(0, 160);
    }
  });
});