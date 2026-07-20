"""
cors_misconfig.py — example plugin

Demonstrates the framework's plugin architecture: any .py file dropped
into plugins/ that exposes a MODULE_NAME string and a
run(target, client, **kwargs) function is automatically discovered and
registered as a new --module option, with zero changes to core code.

This particular plugin performs a non-destructive CORS misconfiguration
check: it sends a request with a clearly external Origin header and
checks whether the server reflects it back in
Access-Control-Allow-Origin (optionally combined with
Access-Control-Allow-Credentials: true), which would allow any website
to make authenticated cross-origin requests against the target.
"""

from utils import logger

MODULE_NAME = "cors"

TEST_ORIGIN = "https://cors-test-9f3a.example.org"


def run(target, client, **kwargs):
    logger.info(f"[CORS] Testing {target} for CORS misconfiguration")
    findings = []

    resp = client.request("GET", target, headers={"Origin": TEST_ORIGIN})
    if resp is None or not hasattr(resp, "headers"):
        findings.append({
            "title": "Target unreachable for CORS assessment",
            "severity": "INFO",
            "evidence": getattr(resp, "error", "No response"),
            "recommendation": "Verify the target URL is reachable and try again.",
        })
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == TEST_ORIGIN:
        severity = "CRITICAL" if acac == "true" else "HIGH"
        findings.append({
            "title": "CORS misconfiguration: arbitrary Origin reflected",
            "severity": severity,
            "evidence": (f"Server reflected the test Origin '{TEST_ORIGIN}' verbatim in "
                        f"Access-Control-Allow-Origin"
                        + (" with Access-Control-Allow-Credentials: true" if acac == "true" else "")
                        + "."),
            "recommendation": "Do not reflect arbitrary Origin values. Maintain an explicit "
                            "allow-list of trusted origins, and never combine a wildcard/"
                            "reflected origin with Allow-Credentials: true.",
        })
        logger.finding(severity, "CORS: arbitrary origin reflected")
    elif acao == "*" and acac == "true":
        # Technically invalid per spec (browsers reject this combo), but
        # still worth flagging as a misconfiguration signal.
        findings.append({
            "title": "CORS misconfiguration: wildcard origin with credentials",
            "severity": "MEDIUM",
            "evidence": "Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true.",
            "recommendation": "Never combine a wildcard Access-Control-Allow-Origin with "
                            "Allow-Credentials: true.",
        })
    else:
        findings.append({
            "title": "No CORS misconfiguration detected",
            "severity": "INFO",
            "evidence": f"Access-Control-Allow-Origin for test origin: '{acao or 'not present'}'.",
            "recommendation": "No action required.",
        })

    return findings