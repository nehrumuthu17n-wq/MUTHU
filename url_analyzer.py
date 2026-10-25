"""
url_analyzer.py
----------------
Heuristic-based phishing / malicious-URL risk analysis.

No external API calls are required, so this module works fully offline.
If network access is available, ANALYZERS_CONFIG in config.py can be
extended to also query real-time threat-intel APIs (Google Safe Browsing,
VirusTotal, PhishTank, etc.) -- see the `enrich_with_external_api` stub
at the bottom of this file for where that would plug in.
"""

import re
import math
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference data used by the heuristics
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "gq", "tk", "ml", "cf", "ga", "work", "click",
    "loan", "men", "win", "review", "country", "kim", "science", "party",
    "biz", "info", "click", "link"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "rebrand.ly", "cutt.ly", "rb.gy", "tiny.cc"
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
    "irs", "gov", "whatsapp", "outlook", "office365", "icloud", "hdfcbank",
    "sbi", "icici", "axisbank", "linkedin"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "confirm", "account", "signin",
    "banking", "webscr", "wp-admin", "reset", "unlock", "suspend",
    "invoice", "billing", "gift", "free", "bonus", "prize", "urgent",
    "click", "download", "claim", "act now", "limited time", "payment",
    "confirm your identity"
]

HOMOGLYPH_CHARS = set("0134")  # crude leetspeak-style substitution markers

KNOWN_SAFE_BRANDS = {
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "bankofamerica", "chase", "wellsfargo", "irs", "gov", "whatsapp",
    "outlook", "office365", "icloud", "hdfcbank", "sbi", "icici", "axisbank",
    "linkedin", "github", "dropbox", "stripe", "slack", "discord", "spotify"
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _is_ip_address(host: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host or ""))


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def analyze_url(raw_url: str) -> dict:
    """
    Returns a dict with:
      score        -> 0-100 trust score contribution (100 = fully trusted)
      findings     -> list of {severity, message}
      details      -> parsed structural info about the URL
    """
    findings = []
    penalty = 0  # accumulated risk penalty (0-100)

    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url  # allow bare domains to be parsed

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme

    if scheme.lower() not in {"http", "https"}:
        penalty += 25
        findings.append({
            "severity": "high",
            "message": f"The link uses the '{scheme or 'unknown'}' scheme, which is unusual for a normal web page and may be used to hide a malicious destination."
        })

    if not host:
        penalty += 30
        findings.append({
            "severity": "high",
            "message": "The URL does not contain a valid hostname, which is a common sign of a malformed or deceptive link."
        })

    if " " in url or "\t" in url:
        penalty += 15
        findings.append({
            "severity": "high",
            "message": "The URL contains whitespace characters, which often appear in phishing links that are deliberately disguised."
        })

    # 1. Scheme check --------------------------------------------------
    if scheme != "https":
        penalty += 12
        findings.append({
            "severity": "medium",
            "message": "The link does not use HTTPS, so data sent to it may not be encrypted."
        })

    # 2. IP address instead of domain name ------------------------------
    if _is_ip_address(host):
        penalty += 25
        findings.append({
            "severity": "high",
            "message": "The link uses a raw IP address instead of a domain name, a common phishing tactic."
        })

    # 3. Suspicious TLD --------------------------------------------------
    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        penalty += 15
        findings.append({
            "severity": "medium",
            "message": f"The domain uses the '.{tld}' extension, which is frequently abused for spam and phishing."
        })

    # 4. URL shorteners ----------------------------------------------------
    if host in URL_SHORTENERS:
        penalty += 10
        findings.append({
            "severity": "medium",
            "message": "The link is a shortened URL, hiding its real destination."
        })

    # 5. "@" symbol in URL (browser redirect trick) -----------------------
    if "@" in url:
        penalty += 20
        findings.append({
            "severity": "high",
            "message": "The URL contains an '@' symbol, which can be used to hide the real destination."
        })

    # 6. Excessive subdomains / length ------------------------------------
    subdomain_count = max(0, host.count(".") - 1)
    if subdomain_count >= 3:
        penalty += 10
        findings.append({
            "severity": "medium",
            "message": "The domain has an unusually large number of subdomains, often used to disguise fake sites."
        })

    if len(url) > 90:
        penalty += 8
        findings.append({
            "severity": "low",
            "message": "The URL is unusually long, which can be used to obscure its true target."
        })

    # 7. Hyphen count in domain --------------------------------------------
    hyphen_count = host.count("-")
    if hyphen_count >= 2:
        penalty += 8
        findings.append({
            "severity": "low",
            "message": "The domain contains multiple hyphens, a pattern common in fake lookalike domains."
        })

    # 8. Suspicious / urgency keywords in path or query --------------------
    combined_lower = (path + " " + query).lower()
    hit_words = [w for w in SUSPICIOUS_WORDS if w in combined_lower]
    if hit_words:
        penalty += min(15, 5 * len(hit_words))
        findings.append({
            "severity": "medium",
            "message": f"The URL path contains sensitive/urgency-related keywords ({', '.join(hit_words[:4])})."
        })

    # 9. Brand impersonation check (typosquatting) --------------------------
    domain_root = host.split(".")[-2] if host.count(".") >= 1 else host
    leet_map = str.maketrans({"1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t"})
    normalized_root = domain_root.translate(leet_map)

    for brand in BRAND_KEYWORDS:
        if brand == domain_root:
            continue
        dist = _levenshtein(normalized_root, brand)
        if 0 < dist <= 2 and len(domain_root) >= 4:
            penalty += 25
            findings.append({
                "severity": "high",
                "message": f"The domain '{host}' closely resembles the trusted brand '{brand}', suggesting typosquatting."
            })
            break
        if brand in normalized_root and normalized_root != brand:
            penalty += 18
            findings.append({
                "severity": "high",
                "message": f"The domain embeds the brand name '{brand}' but is not the brand's official domain."
            })
            break

    # 10. High entropy subdomain (randomly generated) ------------------------
    if subdomain_count >= 1:
        first_label = host.split(".")[0]
        if len(first_label) >= 8 and _shannon_entropy(first_label) > 3.6:
            penalty += 10
            findings.append({
                "severity": "low",
                "message": "The subdomain looks randomly generated, which is typical of automated phishing infrastructure."
            })

    # 11. Excessive login/verification keywords in domain and path -------------
    combined_domain_and_path = f"{host} {path} {query}".lower()
    if any(word in combined_domain_and_path for word in ["login", "verify", "secure", "update", "confirm"]):
        if all(word not in host for word in ["paypal", "google", "amazon", "microsoft", "apple", "netflix", "github", "dropbox"]):
            penalty += 12
            findings.append({
                "severity": "medium",
                "message": "The link uses credential/verification language in an unexpected domain, which is often a sign of a phishing setup."
            })

    # 12. Suspicious numeric/port or parameter abuse ---------------------------
    if parsed.port and parsed.port not in {80, 443}:
        penalty += 8
        findings.append({
            "severity": "medium",
            "message": "The URL uses a non-standard port, which can be used to hide a malicious destination behind a normal-looking domain."
        })
    if "%2f" in query.lower() or "%5c" in query.lower() or "//" in path:
        penalty += 10
        findings.append({
            "severity": "medium",
            "message": "The URL contains encoded or repeated path separators, a common red flag in hidden or cloaked redirect pages."
        })

    # 13. Punycode / internationalized domain (possible homograph attack) ----
    if host.startswith("xn--") or "xn--" in host:
        penalty += 20
        findings.append({
            "severity": "high",
            "message": "The domain uses internationalized (punycode) characters, which can be used to visually spoof a trusted domain."
        })

    penalty = min(penalty, 100)
    score = max(0, 100 - penalty)

    if not findings:
        findings.append({
            "severity": "info",
            "message": "No common phishing indicators were detected in the URL structure."
        })

    return {
        "score": round(score, 1),
        "findings": findings,
        "details": {
            "scheme": scheme,
            "host": host,
            "path": path,
            "is_ip": _is_ip_address(host),
            "is_shortener": host in URL_SHORTENERS,
            "subdomain_count": subdomain_count,
        }
    }


def enrich_with_external_api(url: str) -> dict:
    """
    Placeholder for integrating a real threat-intel API such as Google
    Safe Browsing, VirusTotal, or PhishTank. Wire this up if/when the
    deployment environment has outbound network access and API keys.
    """
    return {"enabled": False, "note": "External threat-intel API not configured."}
