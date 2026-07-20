"""
Module (bonus) - JWT Detection
Scans response bodies, Set-Cookie headers, and the current session's
cookie jar for JWT-shaped tokens, decodes their header/payload (no
signature verification — this is detection, not cracking), and flags
common misconfigurations:
    - alg: none (signature bypass)
    - missing expiration claim
    - expired token still being accepted/present
    - sensitive-looking claim names (password, ssn, secret, etc.)
    - token transmitted over a non-HTTPS connection
"""

import base64
import json
import re
import time

from utils import logger

JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}')
SENSITIVE_CLAIM_KEYS = {"password", "pwd", "secret", "ssn", "credit_card", "api_key", "private_key"}


def run(target, client, jwt_token=None, **kwargs):
    logger.info(f"[JWT] Scanning {target} for JWT tokens")
    findings = []

    candidates = set()
    if jwt_token:
        candidates.add(jwt_token)

    resp = client.get(target)
    if resp is not None and getattr(resp, "text", None):
        candidates.update(JWT_RE.findall(resp.text))

    if resp is not None and hasattr(resp, "headers"):
        set_cookie = resp.headers.get("Set-Cookie", "") if resp.headers else ""
        candidates.update(JWT_RE.findall(set_cookie))

    for name, value in dict(client.session.cookies).items():
        candidates.update(JWT_RE.findall(value))

    if not candidates:
        findings.append({
            "title": "No JWT tokens detected",
            "severity": "INFO",
            "evidence": "Response body, Set-Cookie headers, and the current session's cookie jar "
                        "contain no JWT-shaped strings.",
            "recommendation": "No action required. If the application uses JWTs elsewhere (e.g. an "
                            "Authorization header returned only to a JS client), pass it explicitly "
                            "with --jwt for analysis.",
        })
        logger.success("[JWT] No JWT tokens found")
        return findings

    logger.info(f"[JWT] {len(candidates)} candidate token(s) found")
    is_https = target.lower().startswith("https://")

    for token in candidates:
        findings.extend(_analyze_token(token, is_https, target))

    return findings


def _b64url_decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def _analyze_token(token, is_https, target):
    findings = []
    parts = token.split(".")
    if len(parts) < 2:
        return findings

    short_token = token[:24] + "..." if len(token) > 24 else token

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return findings  # not actually valid JWT header, skip silently

    try:
        payload = json.loads(_b64url_decode(parts[1])) if len(parts) > 1 and parts[1] else {}
    except Exception:
        payload = {}

    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append({
            "title": "JWT using 'alg: none' (signature bypass)",
            "severity": "CRITICAL",
            "evidence": f"Token {short_token} has header alg='none', meaning its contents are "
                        f"entirely unauthenticated and can be forged freely.",
            "recommendation": "Reject tokens with alg='none' server-side; explicitly allow-list "
                            "accepted algorithms rather than trusting the token's own header.",
        })
        logger.finding("CRITICAL", f"JWT alg=none detected ({short_token})")

    if "exp" not in payload:
        findings.append({
            "title": "JWT missing expiration claim",
            "severity": "MEDIUM",
            "evidence": f"Token {short_token} has no 'exp' claim, so it never expires.",
            "recommendation": "Always set a reasonable 'exp' claim and enforce it server-side.",
        })
        logger.finding("MEDIUM", f"JWT missing exp claim ({short_token})")
    else:
        try:
            exp = float(payload["exp"])
            if exp < time.time():
                findings.append({
                    "title": "Expired JWT still present/accepted",
                    "severity": "LOW",
                    "evidence": f"Token {short_token} has an 'exp' claim in the past.",
                    "recommendation": "Confirm the server actually rejects expired tokens rather "
                                    "than relying on the client to discard them.",
                })
        except (TypeError, ValueError):
            pass

    found_sensitive = [k for k in payload.keys() if str(k).lower() in SENSITIVE_CLAIM_KEYS]
    if found_sensitive:
        findings.append({
            "title": "Sensitive data embedded in JWT payload",
            "severity": "HIGH",
            "evidence": f"Token {short_token} payload includes sensitive-looking claim(s): "
                        f"{found_sensitive}. JWT payloads are base64-encoded, not encrypted, and "
                        f"are readable by anyone holding the token.",
            "recommendation": "Never place secrets or sensitive PII directly in JWT claims; store "
                            "a reference/ID instead and look up sensitive data server-side.",
        })
        logger.finding("HIGH", f"Sensitive claims in JWT ({short_token}): {found_sensitive}")

    if not is_https:
        findings.append({
            "title": "JWT observed over an unencrypted connection",
            "severity": "HIGH",
            "evidence": f"Token {short_token} was found while communicating with {target} over "
                        f"plain HTTP, exposing it to network interception.",
            "recommendation": "Serve the application exclusively over HTTPS and mark session "
                            "cookies carrying JWTs as Secure.",
        })
        logger.finding("HIGH", "JWT transmitted over non-HTTPS connection")

    if not findings:
        findings.append({
            "title": "JWT token found — no obvious misconfiguration",
            "severity": "INFO",
            "evidence": f"Token {short_token} decoded with alg='{header.get('alg', 'unknown')}' "
                        f"and a valid-looking expiration; no issues detected via static analysis.",
            "recommendation": "No action required from this check. Signature validity was not "
                            "tested (would require the signing secret/key).",
        })

    return findings