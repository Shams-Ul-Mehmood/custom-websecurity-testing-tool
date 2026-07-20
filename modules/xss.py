"""
Module 3 - Reflected XSS Testing
Tests GET and POST parameters for reflected cross-site scripting using
a small set of safe, uniquely-identifiable canary payloads, each sent
in several basic encodings. Detection is based on verifying the payload
(or its decoded form) is reflected back, unescaped, in the response body.

Requirements covered:
    - GET parameters       (_test_get_params)
    - POST parameters     (_test_post_params)
    - Basic payload encoding (_encode_variants)
    - Detection based on reflected responses (_check_reflection)
    - Parameter discovery (_discover_params) when none are supplied
"""

import html
import re
import urllib.parse as urlparse

from utils import logger

MARKER = "XSS_TEST_9f3a"

# Safe, uniquely-identifiable base payloads (non-destructive canaries)
BASE_PAYLOADS = [
    f"<script>alert('{MARKER}')</script>",
    f"\"'><img src=x onerror=alert('{MARKER}')>",
    f"<svg onload=alert('{MARKER}')>",
]

FORM_INPUT_RE = re.compile(r"<input[^>]*>", re.IGNORECASE)
NAME_ATTR_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
HREF_RE = re.compile(r'href=["\']([^"\']+\?[^"\']+)["\']', re.IGNORECASE)


def run(target, client, params=None, post_params=None, **kwargs):
    logger.info(f"[XSS] Testing {target}")
    findings = []

    parsed = urlparse.urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    query_params = params or dict(urlparse.parse_qsl(parsed.query))
    discovered_get, discovered_post = _discover_params(client, target)

    if not query_params:
        query_params = discovered_get or {"q": "test", "search": "test"}
    if not post_params:
        post_params = discovered_post or {"comment": "test", "message": "test"}

    payload_variants = _build_payload_variants()

    tested = 0
    for param in query_params:
        for label, base_payload, sent_payload in payload_variants:
            tested += 1
            test_params = dict(query_params)
            test_params[param] = sent_payload
            resp = client.get(base_url, params=test_params)
            findings.extend(_check_reflection(resp, "GET", param, base_payload, label, base_url))

    for param in post_params:
        for label, base_payload, sent_payload in payload_variants:
            tested += 1
            test_data = dict(post_params)
            test_data[param] = sent_payload
            resp = client.post(base_url, data=test_data)
            findings.extend(_check_reflection(resp, "POST", param, base_payload, label, base_url))

    logger.success(f"[XSS] {tested} payload/parameter/encoding combinations tested "
                    f"({len(query_params)} GET, {len(post_params)} POST param(s))")

    if not any(f["title"].startswith("Reflected XSS") for f in findings):
        findings.append({
            "title": "No reflected XSS detected",
            "severity": "INFO",
            "evidence": f"{tested} GET/POST parameter+payload+encoding combinations tested "
                        f"with no unencoded reflection.",
            "recommendation": "No action required. Continue to validate/encode all user input on output.",
        })
    return findings


# ---------------------------------------------------------------------
# Basic payload encoding
# ---------------------------------------------------------------------
def _build_payload_variants():
    """For each base payload, produce a small set of basic encodings to
    *send*, while always tracking the underlying raw/base payload that
    would need to end up unescaped in the response for the app to be
    genuinely exploitable. This tests whether naive filters that only
    block the raw string can be bypassed by sending a URL-encoded or
    double-encoded version that the app later decodes and reflects raw."""
    variants = []
    for payload in BASE_PAYLOADS:
        variants.append(("raw", payload, payload))
        variants.append(("url-encoded", payload, urlparse.quote(payload)))
        variants.append(("double-url-encoded", payload, urlparse.quote(urlparse.quote(payload))))
    return variants


# ---------------------------------------------------------------------
# Parameter discovery
# ---------------------------------------------------------------------
def _discover_params(client, target):
    """Fetch the target page and extract candidate GET parameters (from
    links containing a query string) and POST parameters (from <input
    name="..."> fields inside forms), so testing isn't limited to
    manually-supplied parameters."""
    get_params, post_params = {}, {}

    resp = client.get(target)
    if resp is None or not getattr(resp, "text", None):
        return get_params, post_params

    body = resp.text

    for match in HREF_RE.findall(body):
        query = urlparse.urlparse(match).query
        for k, v in urlparse.parse_qsl(query):
            get_params.setdefault(k, v or "test")

    for tag in FORM_INPUT_RE.findall(body):
        name_match = NAME_ATTR_RE.search(tag)
        if name_match and 'type="password"' not in tag.lower() and "type='password'" not in tag.lower():
            post_params.setdefault(name_match.group(1), "test")

    if get_params:
        logger.info(f"[XSS] Discovered GET parameter(s): {list(get_params.keys())}")
    if post_params:
        logger.info(f"[XSS] Discovered POST/form parameter(s): {list(post_params.keys())}")

    return get_params, post_params


# ---------------------------------------------------------------------
# Detection based on reflected responses
# ---------------------------------------------------------------------
def _check_reflection(resp, method, param, base_payload, encoding_label, url):
    """Checks whether the raw/decoded payload (the form that would
    actually execute as HTML/JS) appears unescaped in the response body.
    This is deliberately independent of how the payload was *sent* —
    an app that decodes an encoded payload and reflects it raw is just
    as vulnerable as one that reflects the raw payload directly, and a
    match against the still-encoded string on the wire would only be a
    harmless literal text reflection, not exploitable HTML injection."""
    findings = []
    if resp is None or not hasattr(resp, "text") or resp.text is None:
        return findings

    body = resp.text

    if base_payload in body:
        findings.append({
            "title": f"Reflected XSS in {method} parameter '{param}'",
            "severity": "HIGH",
            "evidence": (f"Payload reflected unencoded at {url} via {method} param '{param}' "
                        f"(sent as {encoding_label}): {base_payload}"),
            "recommendation": "Contextually encode/escape all user-supplied input before reflecting "
                            "it into HTML responses; adopt a strict Content-Security-Policy as "
                            "defense in depth. Ensure filters cannot be bypassed via URL-encoded "
                            "or double-encoded input that the application later decodes.",
        })
        logger.finding("HIGH", f"Reflected XSS via {method} param '{param}' (sent as {encoding_label})")
    elif html.escape(base_payload) in body and MARKER in body:
        # Encoded reflection = generally safe, but note it for completeness
        findings.append({
            "title": f"Input reflected (HTML-encoded) in {method} parameter '{param}'",
            "severity": "INFO",
            "evidence": f"Payload reflected in encoded form for param '{param}' (sent as "
                        f"{encoding_label}) — not exploitable as-is.",
            "recommendation": "No action required; encoding is working correctly for this parameter.",
        })

    return findings