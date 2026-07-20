"""
Module 1 - Security Headers Analyzer
Checks the target's HTTP response headers for the presence and
quality of common security headers.
"""

from utils import logger

CHECKS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "recommendation": "Define a strict Content-Security-Policy to mitigate XSS and "
                        "data-injection attacks (e.g. default-src 'self').",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "recommendation": "Set 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "recommendation": "Set a Referrer-Policy (e.g. 'strict-origin-when-cross-origin') "
                        "to limit referrer leakage.",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "recommendation": "Enable HSTS ('Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains') to enforce HTTPS.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "recommendation": "Define a Permissions-Policy to restrict access to browser "
                        "features (camera, geolocation, etc.).",
    },
}


def run(target, client, **kwargs):
    logger.info(f"[Headers] Requesting {target}")
    findings = []

    resp = client.get(target)
    if resp is None or not getattr(resp, "headers", None):
        findings.append({
            "title": "Target unreachable for header analysis",
            "severity": "INFO",
            "evidence": getattr(resp, "error", "No response received"),
            "recommendation": "Verify the target URL is reachable and try again.",
        })
        return findings

    present_headers = {k.lower(): v for k, v in resp.headers.items()}

    existing = []
    missing = []

    for header, meta in CHECKS.items():
        if header.lower() in present_headers:
            existing.append(header)
            logger.finding("INFO", f"{header}: present ({present_headers[header.lower()]})")
        else:
            missing.append(header)
            findings.append({
                "title": f"Missing security header: {header}",
                "severity": meta["severity"],
                "evidence": f"Header '{header}' not found in response from {target}",
                "recommendation": meta["recommendation"],
            })
            logger.finding(meta["severity"], f"Missing header: {header}")

    # Extra info: server banner disclosure
    if "server" in present_headers:
        findings.append({
            "title": "Server banner disclosure",
            "severity": "LOW",
            "evidence": f"Server header exposes: {present_headers['server']}",
            "recommendation": "Suppress or generalize the 'Server' header to avoid "
                            "revealing software/version details.",
        })

    if "x-powered-by" in present_headers:
        findings.append({
            "title": "X-Powered-By disclosure",
            "severity": "LOW",
            "evidence": f"X-Powered-By header exposes: {present_headers['x-powered-by']}",
            "recommendation": "Remove the 'X-Powered-By' header to reduce technology fingerprinting.",
        })

    logger.success(f"[Headers] {len(existing)} present, {len(missing)} missing")
    return findings
