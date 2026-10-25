"""
scoring.py
----------
Turns a raw analyzer result (score + findings) into the final
user-facing Digital Trust Score payload: a 0-100 score, a risk band,
plain-language reasons, and actionable recommendations.
"""

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}


def risk_band(score: float) -> dict:
    if score >= 80:
        return {"label": "Trusted", "color": "#1a9c4f"}
    if score >= 60:
        return {"label": "Low Risk", "color": "#7cb518"}
    if score >= 40:
        return {"label": "Moderate Risk", "color": "#e6a817"}
    if score >= 20:
        return {"label": "High Risk", "color": "#e6550e"}
    return {"label": "Critical Risk", "color": "#c62828"}


def build_recommendations(content_type: str, score: float, findings: list) -> list:
    recs = []
    high_findings = [f for f in findings if f["severity"] == "high"]

    if score >= 80:
        recs.append("No major red flags found — still stay alert for anything that feels off.")
        return recs

    if content_type == "url":
        if score < 40:
            recs.append("Do not click or enter any personal information on this link.")
            recs.append("Report the link to your organization's IT/security team if received via email or SMS.")
        else:
            recs.append("Proceed with caution — verify the domain matches the official website before entering credentials.")
        if high_findings:
            recs.append("Manually type the organization's known website address into your browser instead of using this link.")

    elif content_type == "email":
        if score < 40:
            recs.append("Do not click any links, download attachments, or reply with personal/financial information.")
            recs.append("Verify the request by contacting the organization directly through official channels (not by replying to this email).")
        else:
            recs.append("Double-check the sender's full email address and be cautious with any links or attachments.")
        recs.append("Report as phishing/spam using your email provider's built-in tools if suspicious.")

    elif content_type == "qr":
        if score < 40:
            recs.append("Do not open the link or follow instructions encoded in this QR code.")
        recs.append("Only scan QR codes from sources you trust; check for stickers placed over original codes in public spaces.")

    elif content_type == "image":
        if score < 50:
            recs.append("Treat this image as potentially edited or AI-generated — verify with a reverse image search before trusting or sharing it.")
        else:
            recs.append("Cross-check the image context/source before relying on it as factual evidence.")

    if not recs:
        recs.append("Exercise general caution and verify through an independent, trusted source.")

    return recs


def finalize(content_type: str, analyzer_result: dict) -> dict:
    score = analyzer_result["score"]
    findings = analyzer_result["findings"]
    band = risk_band(score)
    recommendations = build_recommendations(content_type, score, findings)

    return {
        "content_type": content_type,
        "trust_score": score,
        "risk_level": band["label"],
        "risk_color": band["color"],
        "reasons": findings,
        "recommendations": recommendations,
        "details": analyzer_result.get("details", {}),
        "link_analysis": analyzer_result.get("link_analysis"),
    }
