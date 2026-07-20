"""
Module (bonus) - API Endpoint Testing
Probes for common REST API surface (discovery paths, OpenAPI/Swagger
specs) and performs light, non-destructive checks:
- API documentation / spec exposure
- HTTP verb enumeration via OPTIONS (state-changing methods open?)
- Presence of an endpoint that responds without any auth/session
    context (flagged conservatively as informational — confirming a
    genuine broken-access-control issue needs a valid vs. invalid
    credential comparison, which is out of scope for a safe default scan)
"""

import json
import urllib.parse as urlparse

from utils import logger

DISCOVERY_PATHS = [
    "api", "api/v1", "api/v2", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml", "api-docs", "api/swagger.json",
    "v2/api-docs", "graphql", ".well-known/openapi.yaml",
]

STATE_CHANGING_METHODS = {"PUT", "DELETE", "PATCH"}


def run(target, client, **kwargs):
    logger.info(f"[API] Probing {target} for API surface")
    findings = []

    parsed = urlparse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}/"

    discovered = []
    for path in DISCOVERY_PATHS:
        url = urlparse.urljoin(base, path)
        resp = client.get(url)
        if resp is None or not hasattr(resp, "status_code"):
            continue
        if resp.status_code == 200 and resp.text:
            discovered.append((path, url, resp))

    for path, url, resp in discovered:
        severity = "MEDIUM" if any(k in path for k in ("swagger", "openapi", "api-docs")) else "INFO"
        findings.append({
            "title": f"API surface discovered: /{path}",
            "severity": severity,
            "evidence": f"HTTP 200 returned for {url}",
            "recommendation": "Ensure API documentation endpoints are not exposed in production, "
                            "or are protected behind authentication; review the exposed spec for "
                            "undocumented or sensitive endpoints.",
        })
        logger.finding(severity, f"API surface: /{path} -> {url}")

        # If it looks like a machine-readable spec, try to enumerate its paths
        findings.extend(_analyze_spec(resp.text, url))

    # HTTP verb enumeration on the base target
    findings.extend(_check_verbs(client, target))

    if not discovered:
        findings.append({
            "title": "No common API surface detected",
            "severity": "INFO",
            "evidence": f"{len(DISCOVERY_PATHS)} common API discovery paths tested; none exposed.",
            "recommendation": "No action required.",
        })

    logger.success(f"[API] Probed {len(DISCOVERY_PATHS)} discovery paths, "
                    f"{len(discovered)} exposed")
    return findings


def _analyze_spec(body, url):
    findings = []
    try:
        spec = json.loads(body)
    except Exception:
        return findings

    paths = spec.get("paths")
    if isinstance(paths, dict) and paths:
        endpoint_count = len(paths)
        sample = list(paths.keys())[:10]
        findings.append({
            "title": "OpenAPI/Swagger spec enumerates API endpoints",
            "severity": "MEDIUM",
            "evidence": f"{url} declares {endpoint_count} endpoint(s), including: {sample}",
            "recommendation": "Review each declared endpoint for proper authentication and "
                            "authorization; remove undocumented/debug endpoints from the spec "
                            "before it reaches production.",
        })
    return findings


def _check_verbs(client, target):
    findings = []
    resp = client.request("OPTIONS", target)

    if resp is None or not hasattr(resp, "headers"):
        return findings

    allow = resp.headers.get("Allow", "")
    if not allow:
        return findings

    allowed_methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    risky = allowed_methods & STATE_CHANGING_METHODS

    if risky:
        findings.append({
            "title": "State-changing HTTP methods enabled",
            "severity": "MEDIUM",
            "evidence": f"OPTIONS request to {target} advertises: {', '.join(sorted(allowed_methods))} "
                        f"(including state-changing method(s): {', '.join(sorted(risky))}).",
            "recommendation": "Confirm PUT/DELETE/PATCH (and similar) endpoints enforce proper "
                            "authentication and authorization; disable methods that aren't "
                            "explicitly needed.",
        })
        logger.finding("MEDIUM", f"State-changing methods advertised: {risky}")

    return findings