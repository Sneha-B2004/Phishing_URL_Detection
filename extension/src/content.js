(() => {
  const existing = document.getElementById("phishguard-overlay");
  const existingClose = document.getElementById("phishguard-close");

  // Toggle overlay: if it exists, remove it and exit
  if (existing || existingClose) {
    if (existing) existing.remove();
    if (existingClose) existingClose.remove();
    return;
  }

  // Close button
  const closeBtn = document.createElement("div");
  closeBtn.id = "phishguard-close";
  closeBtn.textContent = "Close";
  closeBtn.onclick = () => {
    const frame = document.getElementById("phishguard-overlay");
    const btn = document.getElementById("phishguard-close");
    if (frame) frame.remove();
    if (btn) btn.remove();
  };
  document.documentElement.appendChild(closeBtn);

  // Iframe overlay
  const iframe = document.createElement("iframe");
  iframe.id = "phishguard-overlay";
  iframe.src = chrome.runtime.getURL("src/iframe.html");
  document.documentElement.appendChild(iframe);

  // Send current tab URL to iframe after load
  iframe.addEventListener("load", () => {
    iframe.contentWindow.postMessage(
      { type: "PHISHGUARD_URL", url: window.location.href },
      "*"
    );
  });
})();