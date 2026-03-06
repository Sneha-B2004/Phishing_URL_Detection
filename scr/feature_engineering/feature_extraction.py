import re
import requests
import socket
import ssl
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime


def extract_features(url):

    features = []

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1️⃣ Having IP Address
    try:
        socket.inet_aton(domain)
        features.append(-1)
    except:
        features.append(1)

    # 2️⃣ URL Length
    if len(url) < 54:
        features.append(1)
    elif 54 <= len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 3️⃣ Shortening Service
    shortening = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co"
    features.append(-1 if re.search(shortening, url) else 1)

    # 4️⃣ @ symbol
    features.append(-1 if "@" in url else 1)

    # 5️⃣ Double slash redirect
    features.append(-1 if url.rfind("//") > 6 else 1)

    # 6️⃣ Prefix-Suffix (hyphen in domain)
    features.append(-1 if "-" in domain else 1)

    # 7️⃣ Subdomain count
    if domain.count('.') > 2:
        features.append(-1)
    else:
        features.append(1)

    # 8️⃣ HTTPS check
    features.append(1 if parsed.scheme == "https" else -1)

    # 9️⃣ SSL Certificate Validity
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        features.append(1)
    except:
        features.append(-1)

    # 🔟 WHOIS Domain Age
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days

        if age < 180:
            features.append(-1)
        else:
            features.append(1)
    except:
        features.append(-1)

    # 1️⃣1️⃣ DNS Record
    try:
        socket.gethostbyname(domain)
        features.append(1)
    except:
        features.append(-1)

    # 1️⃣2️⃣ Fetch page & check iframe
    try:
        response = requests.get(url, timeout=3)
        soup = BeautifulSoup(response.text, "html.parser")

        iframes = soup.find_all("iframe")
        features.append(-1 if len(iframes) > 0 else 1)

        # suspicious keywords
        suspicious_keywords = ["login", "verify", "update", "secure", "account"]
        if any(word in url.lower() for word in suspicious_keywords):
            features.append(-1)
        else:
            features.append(1)

    except:
        features.append(-1)
        features.append(-1)

    # Fill remaining features to reach 30
    while len(features) < 30:
        features.append(1)

    return features
