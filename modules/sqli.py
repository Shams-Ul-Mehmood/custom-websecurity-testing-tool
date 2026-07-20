"""
Module 4 - SQL Injection Testing (safe / non-destructive)
Performs error-based, boolean-based, and optional time-based checks
using benign payloads. Never attempts UNION-based data extraction or
destructive statements (no DROP/DELETE/UPDATE/INSERT payloads).
"""

import re
import time
import urllib.parse as urlparse

from utils import logger

ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"pg_query\(\)",
    r"sqlite3\.OperationalError",
    r"ORA-\d{5}",
    r"microsoft odbc",
    r"System\.Data\.SqlClient",
]

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "';--", "1' AND '1'='1"]
BOOLEAN_TRUE = "1' OR '1'='1"
BOOLEAN_FALSE = "1' AND '1'='2"
TIME_PAYLOAD = "1' AND SLEEP(3)-- -"
TIME_THRESHOLD = 2.5


def run(target, client, params=None, test_time_based=False, **kwargs):
    logger.info(f"[SQLi] Testing {target}")
    findings = []

    parsed = urlparse.urlparse(target)
    query_params = params or dict(urlparse.parse_qsl(parsed.query)) or {"id": "1"}
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    error_re = re.compile("|".join(ERROR_PATTERNS), re.IGNORECASE)

    for param in query_params:
        # --- error-based ---
        for payload in ERROR_PAYLOADS:
            test_params = dict(query_params)
            test_params[param] = payload
            resp = client.get(base_url, params=test_params)
            if resp is not None and getattr(resp, "text", None) and error_re.search(resp.text):
                findings.append({
                    "title": f"Possible SQL injection (error-based) in parameter '{param}'",
                    "severity": "CRITICAL",
                    "evidence": f"SQL error signature returned for payload '{payload}' on param '{param}'.",
                    "recommendation": "Use parameterized queries / prepared statements for all "
                                    "database access; never concatenate user input into SQL.",
                })
                logger.finding("CRITICAL", f"Error-based SQLi signature in '{param}'")
                break  # one confirmation per param is enough

        # --- boolean-based ---
        base_params = dict(query_params)
        true_params = dict(query_params); true_params[param] = BOOLEAN_TRUE
        false_params = dict(query_params); false_params[param] = BOOLEAN_FALSE

        r_base = client.get(base_url, params=base_params)
        r_true = client.get(base_url, params=true_params)
        r_false = client.get(base_url, params=false_params)

        if all(r is not None and hasattr(r, "text") and r.text is not None
            for r in (r_base, r_true, r_false)):
            len_true = len(r_true.text)
            len_false = len(r_false.text)
            if abs(len_true - len_false) > 50 and r_true.status_code == 200:
                findings.append({
                    "title": f"Possible SQL injection (boolean-based) in parameter '{param}'",
                    "severity": "HIGH",
                    "evidence": (f"Response length differs significantly between TRUE "
                                f"({len_true} bytes) and FALSE ({len_false} bytes) conditions "
                                f"for param '{param}'."),
                    "recommendation": "Use parameterized queries and validate/sanitize all "
                                    "user-supplied input server-side.",
                })
                logger.finding("HIGH", f"Boolean-based SQLi signal in '{param}'")

        # --- time-based (optional, off by default to keep scans fast/safe) ---
        if test_time_based:
            t_params = dict(query_params)
            t_params[param] = TIME_PAYLOAD
            start = time.time()
            r_time = client.get(base_url, params=t_params)
            elapsed = time.time() - start
            if r_time is not None and elapsed >= TIME_THRESHOLD:
                findings.append({
                    "title": f"Possible SQL injection (time-based) in parameter '{param}'",
                    "severity": "HIGH",
                    "evidence": f"Response for param '{param}' delayed by {elapsed:.2f}s using a SLEEP payload.",
                    "recommendation": "Use parameterized queries; review database error handling "
                                    "and disable verbose SQL errors in production.",
                })
                logger.finding("HIGH", f"Time-based SQLi signal in '{param}' ({elapsed:.2f}s)")

    if not any("SQL injection" in f["title"] for f in findings):
        findings.append({
            "title": "No SQL injection indicators detected",
            "severity": "INFO",
            "evidence": f"Tested {len(query_params)} parameter(s) with error/boolean-based payloads; "
                        f"no anomalies observed.",
            "recommendation": "No action required. Continue using parameterized queries.",
        })

    logger.success("[SQLi] SQL injection testing complete")
    return findings
