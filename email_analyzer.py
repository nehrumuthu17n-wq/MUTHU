"""
email_analyzer.py
------------------
Heuristic analysis of raw email content (headers + body pasted as text)
to flag phishing / social-engineering indicators. Also extracts any
embedded URLs and re-uses url_analyzer for a deeper look at each link.
"""

import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    backend_dir = Path(__file__).resolve().parents[1]
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
    from analyzers.url_analyzer import analyze_url
else:
    from .url_analyzer import analyze_url

URGENCY_PHRASES = [
    "act now", "verify your account", "urgent", "immediately", "suspended",
    "click here", "limited time", "final notice", "your account has been",
    "unusual activity", "confirm your identity", "restricted", "expire",
    "winner", "claim your", "password expires", "security alert"
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear member",
    "dear account holder", "hello user"
]

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "mail.com", "gmx.com", "icloud.com"
}

URL_REGEX = re.compile(r"(https?://[^\s<>\"')]+|www\.[^\s<>\"')]+)", re.IGNORECASE)
EMAIL_ADDR_REGEX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _extract_display_name_and_domain(from_header: str):
    """
    Parses something like: 'PayPal Support <support@paypa1-secure.com>'
    into display name = 'PayPal Support', domain = 'paypa1-secure.com'
    """
    match = re.match(r"^(.*?)<([^>]+)>$", from_header.strip())
    if match:
        display_name = match.group(1).strip().strip('"')
        addr = match.group(2).strip()
    else:
        display_name = ""
        addr = from_header.strip()
    domain = addr.split("@")[-1].lower() if "@" in addr else ""
    return display_name, addr, domain


def analyze_email(from_header: str, subject: str, body: str) -> dict:
    findings = []
    penalty = 0

    subject = subject or ""
    body = body or ""
    from_header = from_header or ""

    display_name, sender_addr, sender_domain = _extract_display_name_and_domain(from_header)

    # 1. Display name impersonates a brand not matching the domain -------
    lowered_name = display_name.lower()
    for brand in ["paypal", "amazon", "microsoft", "apple", "bank", "google",
                  "netflix", "irs", "support", "security team"]:
        if brand in lowered_name and brand.replace(" ", "") not in sender_domain.replace("-", ""):
            penalty += 25
            findings.append({
                "severity": "high",
                "message": f"The sender's display name mentions '{display_name}' but the actual email domain "
                            f"'{sender_domain or 'unknown'}' does not match, a classic spoofing sign."
            })
            break

    # 2. Sender uses a free/personal email domain for a "business" email --
    if sender_domain in FREE_EMAIL_DOMAINS and any(
        k in lowered_name for k in ["support", "security", "billing", "admin", "service", "team"]
    ):
        penalty += 15
        findings.append({
            "severity": "medium",
            "message": f"The sender claims to be an official team but is emailing from a free/personal domain ({sender_domain})."
        })

    # 3. Urgency / pressure language ---------------------------------------
    text_lower = (subject + " " + body).lower()
    hit_phrases = [p for p in URGENCY_PHRASES if p in text_lower]
    if hit_phrases:
        penalty += min(20, 5 * len(hit_phrases))
        findings.append({
            "severity": "medium",
            "message": f"The message uses urgency/pressure language commonly seen in phishing "
                       f"(e.g. \"{hit_phrases[0]}\")."
        })

    # 4. Generic greeting instead of personalized name ---------------------
    if any(g in text_lower for g in GENERIC_GREETINGS):
        penalty += 8
        findings.append({
            "severity": "low",
            "message": "The email uses a generic greeting rather than your actual name, common in mass phishing campaigns."
        })

    # 5. Requests for sensitive info ----------------------------------------
    sensitive_asks = ["password", "otp", "one-time password", "credit card", "cvv",
                       "ssn", "social security", "pin number", "bank account number"]
    hit_sensitive = [w for w in sensitive_asks if w in text_lower]
    if hit_sensitive:
        penalty += 20
        findings.append({
            "severity": "high",
            "message": f"The email asks for sensitive information ({', '.join(hit_sensitive[:3])}), "
                       "which legitimate organizations rarely request via email."
        })

    # 6. Mismatched / suspicious reply-to style addresses embedded in body ---
    body_addrs = set(EMAIL_ADDR_REGEX.findall(body))
    if sender_domain and any(sender_domain not in a for a in body_addrs) and body_addrs:
        # Only flag if there's a clearly different domain being pushed for replies
        other_domains = {a.split("@")[-1].lower() for a in body_addrs} - {sender_domain}
        if other_domains:
            penalty += 6
            findings.append({
                "severity": "low",
                "message": "The email body references a different reply/contact domain than the sender's address."
            })

    # 7. Extract & analyze embedded links -----------------------------------
    urls = list(dict.fromkeys(URL_REGEX.findall(body)))  # de-dup, preserve order
    link_results = []
    if urls:
        worst_link_score = 100
        for u in urls[:8]:  # cap to avoid excessive analysis
            result = analyze_url(u)
            link_results.append({"url": u, **result})
            worst_link_score = min(worst_link_score, result["score"])
        if worst_link_score < 60:
            penalty += (100 - worst_link_score) * 0.3
            findings.append({
                "severity": "high",
                "message": "One or more links embedded in the email show strong phishing indicators."
            })
    else:
        findings.append({
            "severity": "info",
            "message": "No hyperlinks were found in the email body."
        })

    penalty = min(penalty, 100)
    score = max(0, 100 - penalty)

    if len(findings) == (1 if not hit_phrases else 0) and not any(
        f["severity"] != "info" for f in findings
    ):
        pass  # keep as-is; info-only findings already appended naturally

    return {
        "score": round(score, 1),
        "findings": findings,
        "details": {
            "display_name": display_name,
            "sender_address": sender_addr,
            "sender_domain": sender_domain,
            "urls_found": len(urls),
        },
        "link_analysis": link_results,
    }


if __name__ == "__main__":
    sample_email = {
        "from": "PayPal Security <security@paypal-support.com>",
        "subject": "Your account was suspended",
        "body": "Urgent action required. Verify your account now: https://paypal-security-login.com/reset"
    }
    result = analyze_email(
        sample_email["from"],
        sample_email["subject"],
        sample_email["body"],
    )
    print(result)
