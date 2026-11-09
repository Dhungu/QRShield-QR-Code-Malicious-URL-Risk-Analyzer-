"""Rule-based URL risk analysis used by the scan route.

Fully offline: never fetches the URL or follows redirects, so scanning a
link can't itself trigger a request to a malicious or internal server
(SSRF). Returns checks as one ordered list (the order they run in) instead
of two separately-grouped pass/warn lists, so a scan can be replayed as a
single sequential log and so each check maps to one ScanCheck row.
"""

import ipaddress
from datetime import datetime
from urllib.parse import unquote, urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "password",
    "account", "update", "secure", "banking",
    "signin", "confirm", "wallet", "payment"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "goo.gl", "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
}

# TLDs that show up disproportionately in phishing/spam campaigns.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click", "loan"
}


def analyze_url(url):
    """Analyze a URL using simple, explainable cybersecurity checks."""
    score = 0
    checks = []  # list of {"text": str, "status": "pass" | "warn"}

    def ok(text):
        checks.append({"text": text, "status": "pass"})

    def flag(text, points):
        nonlocal score
        score += points
        checks.append({"text": text, "status": "warn"})

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if parsed.scheme.lower() == "https":
        ok("Uses HTTPS encryption")
    else:
        flag("Website does not use HTTPS", 10)

    try:
        ipaddress.ip_address(hostname)
        flag("URL uses an IP address instead of a domain name", 25)
    except ValueError:
        ok("Uses a domain name")

    if len(url) > 120:
        flag("URL is unusually long", 10)
    else:
        ok("URL length looks normal")

    if "@" in url:
        flag("URL contains an @ symbol", 20)
    else:
        ok("No @ symbol detected")

    found_words = [word for word in SUSPICIOUS_KEYWORDS if word in url.lower()]
    if found_words:
        flag(
            "Contains potentially sensitive keywords: " + ", ".join(found_words[:3]),
            min(15, len(found_words) * 5),
        )
    else:
        ok("No common suspicious keywords detected")

    if hostname in URL_SHORTENERS:
        flag("Uses a URL shortening service", 15)
    else:
        ok("No common URL shortener detected")

    if "xn--" in hostname:
        flag("Domain contains Punycode, which can be used in look-alike domains", 20)
    else:
        ok("No Punycode detected")

    if hostname.count(".") >= 3:
        flag("Domain contains an unusually high number of subdomains", 10)
    else:
        ok("Domain structure looks normal")

    if hostname.count("-") >= 2:
        flag("Domain contains multiple hyphens, common in look-alike domains", 10)
    else:
        ok("Domain has a normal hyphen count")

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        flag(f"Uses a top-level domain (.{tld}) often associated with abuse", 10)
    else:
        ok("Top-level domain has no known abuse pattern")

    decoded_url = unquote(url)
    if "%" in url and decoded_url != url:
        flag("URL contains percent-encoded characters that may hide its true content", 10)
    else:
        ok("No obfuscating percent-encoding detected")

    score = min(score, 100)

    if score < 30:
        level = "LOW RISK"
        css_class = "low"
        recommendation = (
            "This URL shows relatively few suspicious characteristics. "
            "Still verify the domain before entering sensitive information."
        )
    elif score < 60:
        level = "MEDIUM RISK"
        css_class = "medium"
        recommendation = (
            "Exercise caution. Some characteristics of this URL may indicate "
            "a potentially suspicious website. Verify the destination before continuing."
        )
    else:
        level = "HIGH RISK"
        css_class = "high"
        recommendation = (
            "Avoid opening this URL unless you can independently verify the destination. "
            "Do not enter passwords, payment information, or other sensitive data."
        )

    return {
        "url": url,
        "score": score,
        "level": level,
        "css_class": css_class,
        "checks": checks,
        "recommendation": recommendation,
        "hostname": hostname or "N/A",
        "protocol": parsed.scheme.upper() or "N/A",
        "length": len(url),
        "timestamp": datetime.now().strftime("%d %b %Y, %I:%M %p"),
    }
