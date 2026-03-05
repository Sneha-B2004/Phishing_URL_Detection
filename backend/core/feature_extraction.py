import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import numpy as np
import requests
import whois
from bs4 import BeautifulSoup


def extract_features(url: str):
    """
    Returns a 2D numpy array shaped (1, 30) for sklearn models.
    """
    features = []

    # Normalize URL: urlparse needs scheme to properly detect hostname
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""  # safer than netloc (removes port)
    domain = host

    # 1) Having IP Address
    try:
        socket.inet_aton(domain)
        features.append(-1)
    except:
        features.append(1)

    # 2) URL Length
    if len(url) < 54:
        features.append(1)
    elif 54 <= len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 3) Shortening Service
    shortening = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co"
    features.append(-1 if re.search(shortening, url) else 1)

    # 4) @ symbol
    features.append(-1 if "@" in url else 1)

    # 5) Double slash redirect
    features.append(-1 if url.rfind("//") > 6 else 1)

    # 6) Prefix-Suffix (hyphen in domain)
    features.append(-1 if "-" in domain else 1)

    # 7) Subdomain count
    features.append(-1 if domain.count(".") > 2 else 1)

    # 8) HTTPS check
    features.append(1 if parsed.scheme == "https" else -1)

    # 9) SSL Certificate Validity (only meaningful if https and host exists)
    try:
        if parsed.scheme == "https" and domain:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, 443))
            features.append(1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # 10) WHOIS Domain Age
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.now() - creation_date).days
            features.append(-1 if age < 180 else 1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # 11) DNS Record
    try:
        socket.gethostbyname(domain)
        features.append(1)
    except:
        features.append(-1)

    # 12) Fetch page & check iframe + keywords
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")

        iframes = soup.find_all("iframe")
        features.append(-1 if len(iframes) > 0 else 1)

        suspicious_keywords = ["login", "verify", "update", "secure", "account"]
        features.append(-1 if any(word in url.lower() for word in suspicious_keywords) else 1)

    except:
        # if fetch fails, treat as suspicious
        features.append(-1)
        features.append(-1)

    # Fill remaining features to reach 30
    while len(features) < 30:
        features.append(1)

    # IMPORTANT: return 2D shape (1, 30)
    X = np.array(features, dtype=float).reshape(1, -1)
    return X