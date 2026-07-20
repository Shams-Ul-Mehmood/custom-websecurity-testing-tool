"""
Module 2 - Authentication Assessment
Performs five non-destructive checks against a login endpoint:
    1. Weak password policy       (_check_password_policy)
    2. Username enumeration       (_check_username_enumeration)
    3. Login response differences (_check_response_differences)
    4. Account lockout detection  (_check_account_lockout)
    5. Session cookie analysis    (_analyze_cookies)

NOTE: This module intentionally avoids brute forcing real credentials or
creating real accounts. It uses a very small number of clearly-fake test
values to observe *differences* in behavior, which is sufficient to flag
risk without attempting unauthorized access.
"""

import re
import statistics
import time

from utils import logger

FAKE_USERS = ["definitely_not_a_real_user_12345", "admin"]
FAKE_PASSWORD = "Wrong_Password_123!"

# Passwords that a policy-compliant system should reject
WEAK_PASSWORDS = ["123456", "password", "abc"]

PASSWORD_FIELD_RE = re.compile(
    r"<input[^>]*type=[\"']password[\"'][^>]*>", re.IGNORECASE)
ATTR_RE = re.compile(r'(\w[\w-]*)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)


def run(target, client, login_path=None, register_path=None,
        username_field="username", password_field="password", **kwargs):
    logger.info(f"[Auth] Assessing authentication at {target}")
    findings = []

    login_url = login_path or target

    resp = client.get(login_url)
    if resp is None or not hasattr(resp, "headers"):
        findings.append({
            "title": "Target unreachable for authentication assessment",
            "severity": "INFO",
            "evidence": getattr(resp, "error", "No response"),
            "recommendation": "Verify the login URL is correct and reachable.",
        })
        return findings

    fields = (username_field, password_field)

    # 1. Weak password policy
    findings.extend(_check_password_policy(client, resp, register_path, fields))

    # 2. Username enumeration
    findings.extend(_check_username_enumeration(client, login_url, fields))

    # 3. Login response differences (content + timing)
    findings.extend(_check_response_differences(client, login_url, fields))

    # 4. Account lockout detection
    findings.extend(_check_account_lockout(client, login_url, fields))

    # 5. Session cookie analysis
    findings.extend(_analyze_cookies(resp))

    logger.success("[Auth] Authentication assessment complete")
    return findings


# ---------------------------------------------------------------------
# 1. Weak password policy
# ---------------------------------------------------------------------
def _check_password_policy(client, login_resp, register_path, fields):
    """Non-destructive weak-password-policy check.

    Two techniques, neither of which creates a real account or submits
    real credentials:
        a) Static analysis of the <input type="password"> markup on the
            login page for client-side policy hints (minlength/pattern).
        b) If a registration endpoint is explicitly provided via
            --register-path, submit an obviously-fake, throwaway account
        with a very weak password and see whether it's accepted or
        rejected by policy validation (never done against login itself).
    """
    findings = []
    username_field, password_field = fields

    body = getattr(login_resp, "text", "") or ""
    password_inputs = PASSWORD_FIELD_RE.findall(body)

    if password_inputs:
        has_minlength = False
        has_pattern = False
        for tag in password_inputs:
            attrs = dict(ATTR_RE.findall(tag))
            if "minlength" in {k.lower() for k in attrs}:
                has_minlength = True
            if "pattern" in {k.lower() for k in attrs}:
                has_pattern = True

        if not has_minlength and not has_pattern:
            findings.append({
                "title": "No client-side password policy enforcement detected",
                "severity": "LOW",
                "evidence": "Password input field(s) on the login/registration form carry no "
                            "'minlength' or 'pattern' attribute enforcing complexity.",
                "recommendation": "Enforce a strong password policy (minimum length, character "
                                "variety) both client-side (UX) and, critically, server-side.",
            })
            logger.finding("LOW", "No client-side password policy hints found")
    else:
        findings.append({
            "title": "Password policy could not be assessed",
            "severity": "INFO",
            "evidence": "No <input type=\"password\"> field found on the supplied login URL; "
                        "point --login-path at the actual login/registration form for a full check.",
            "recommendation": "Manually verify the application enforces a minimum password length "
                            "(e.g. 12+ characters) and rejects common/breached passwords.",
        })

    # Optional active check against an explicit, opt-in registration endpoint only
    if register_path:
        accepted_weak = []
        for weak_pw in WEAK_PASSWORDS:
            throwaway_user = f"sectest_{int(time.time())}_{weak_pw[:3]}"
            r = client.post(register_path, data={
                username_field: throwaway_user,
                password_field: weak_pw,
            })
            if r is not None and hasattr(r, "status_code") and r.status_code in (200, 201, 302):
                body_l = (r.text or "").lower()
                rejected_terms = ["too short", "weak password", "password must", "does not meet"]
                if not any(t in body_l for t in rejected_terms):
                    accepted_weak.append(weak_pw)
            time.sleep(0.3)

        if accepted_weak:
            findings.append({
                "title": "Weak passwords accepted by registration policy",
                "severity": "HIGH",
                "evidence": f"Registration endpoint appeared to accept weak password(s): {accepted_weak}",
                "recommendation": "Enforce server-side minimum length/complexity requirements and "
                                "reject commonly-used/breached passwords (e.g. via a blocklist).",
            })
            logger.finding("HIGH", f"Weak passwords accepted: {accepted_weak}")

    return findings


# ---------------------------------------------------------------------
# 2. Username enumeration
# ---------------------------------------------------------------------
def _check_username_enumeration(client, login_url, fields):
    username_field, password_field = fields
    findings = []

    responses = {}
    for user in FAKE_USERS:
        r = client.post(login_url, data={username_field: user, password_field: FAKE_PASSWORD})
        if r is not None and hasattr(r, "text"):
            responses[user] = {
                "status": r.status_code,
                "length": len(r.text or ""),
                "message": _extract_error_message(r.text or ""),
            }
        time.sleep(0.3)

    if len(responses) >= 2:
        statuses = {u: d["status"] for u, d in responses.items()}
        lengths = {u: d["length"] for u, d in responses.items()}
        messages = {u: d["message"] for u, d in responses.items()}

        differs = (len(set(statuses.values())) > 1
                or len(set(lengths.values())) > 1
                or len(set(messages.values())) > 1)

        if differs:
            findings.append({
                "title": "Possible username enumeration via response differences",
                "severity": "MEDIUM",
                "evidence": (f"Differing responses for nonexistent vs. common username: "
                            f"statuses={statuses}, lengths={lengths}, messages={messages}"),
                "recommendation": "Return an identical, generic error message and HTTP status for "
                                "both invalid usernames and valid-username/invalid-password cases.",
            })
            logger.finding("MEDIUM", "Username enumeration signal detected")
        else:
            logger.info("[Auth] No obvious response differences between test usernames")

    return findings


# ---------------------------------------------------------------------
# 3. Login response differences (content AND timing)
# ---------------------------------------------------------------------
def _check_response_differences(client, login_url, fields, samples=3):
    username_field, password_field = fields
    findings = []

    valid_looking_times = []
    invalid_times = []

    for _ in range(samples):
        t0 = time.time()
        client.post(login_url, data={username_field: FAKE_USERS[1],  # "admin"
                                    password_field: FAKE_PASSWORD})
        valid_looking_times.append(time.time() - t0)
        time.sleep(0.2)

        t0 = time.time()
        client.post(login_url, data={username_field: FAKE_USERS[0],  # random/nonexistent
                                    password_field: FAKE_PASSWORD})
        invalid_times.append(time.time() - t0)
        time.sleep(0.2)

    avg_valid = statistics.mean(valid_looking_times)
    avg_invalid = statistics.mean(invalid_times)
    delta = abs(avg_valid - avg_invalid)

    if delta > 0.3:  # 300ms average difference is a usable side channel
        findings.append({
            "title": "Timing-based login response difference detected",
            "severity": "MEDIUM",
            "evidence": (f"Average response time for a common username ('admin') was "
                        f"{avg_valid:.3f}s vs {avg_invalid:.3f}s for a nonexistent username "
                        f"(Δ={delta:.3f}s over {samples} samples)."),
            "recommendation": "Ensure authentication logic takes constant time regardless of "
                            "whether the supplied username exists (e.g. always perform a "
                            "password hash comparison, even for unknown users).",
        })
        logger.finding("MEDIUM", f"Timing side-channel detected (Δ={delta:.3f}s)")
    else:
        logger.info(f"[Auth] No significant timing difference detected (Δ={delta:.3f}s)")

    return findings


def _extract_error_message(body):
    """Best-effort extraction of a short error snippet for comparison."""
    lower = body.lower()
    for keyword in ["invalid", "incorrect", "error", "not found", "denied"]:
        idx = lower.find(keyword)
        if idx != -1:
            return body[max(0, idx - 20):idx + 40].strip()
    return body[:60].strip()


# ---------------------------------------------------------------------
# 4. Account lockout detection
# ---------------------------------------------------------------------
def _check_account_lockout(client, login_url, fields, attempts=4):
    username_field, password_field = fields
    findings = []

    lockout_triggered = False
    last_status = None
    for i in range(attempts):
        r = client.post(login_url, data={username_field: FAKE_USERS[0],
                                        password_field: f"wrong{i}"})
        if r is None or not hasattr(r, "status_code"):
            break
        last_status = r.status_code
        body = (r.text or "").lower()
        if any(term in body for term in ["locked", "too many attempts", "try again later"]):
            lockout_triggered = True
            break
        time.sleep(0.3)

    if lockout_triggered:
        findings.append({
            "title": "Account lockout mechanism detected",
            "severity": "INFO",
            "evidence": "Lockout / rate-limit message observed after repeated failed logins.",
            "recommendation": "Good practice — ensure lockout thresholds and durations are "
                            "tuned to prevent both brute force and denial-of-service abuse.",
        })
    else:
        findings.append({
            "title": "No account lockout detected after repeated failed logins",
            "severity": "MEDIUM",
            "evidence": f"{attempts} failed login attempts returned status {last_status} with "
                        f"no lockout indication.",
            "recommendation": "Implement account lockout, CAPTCHA, or progressive delays after "
                            "repeated failed login attempts to mitigate brute-force attacks.",
        })
        logger.finding("MEDIUM", "No lockout mechanism observed")

    return findings


# ---------------------------------------------------------------------
# 5. Session cookie analysis
# ---------------------------------------------------------------------
def _analyze_cookies(resp):
    """5. Session cookie analysis — flags session/auth cookies missing
    Secure, HttpOnly, or SameSite attributes."""
    findings = []
    cookies = resp.headers.get("Set-Cookie") if hasattr(resp, "headers") else None
    # requests only exposes one Set-Cookie via .headers; use raw jar if available
    jar_cookies = getattr(resp, "cookies", None)

    if not cookies and not jar_cookies:
        return findings

    session_like = re.compile(r"(sess|auth|token|login)", re.I)

    if jar_cookies:
        for c in jar_cookies:
            if not session_like.search(c.name):
                continue
            issues = []
            if not getattr(c, "secure", False):
                issues.append("missing Secure flag")
            httponly = c._rest.get("HttpOnly") if hasattr(c, "_rest") else None
            if httponly is None:
                issues.append("missing HttpOnly flag")
            samesite = c._rest.get("SameSite") if hasattr(c, "_rest") else None
            if not samesite:
                issues.append("missing SameSite attribute")

            if issues:
                findings.append({
                    "title": f"Insecure session cookie attributes on '{c.name}'",
                    "severity": "MEDIUM",
                    "evidence": f"Cookie '{c.name}' issues: {', '.join(issues)}",
                    "recommendation": "Set Secure, HttpOnly, and SameSite=Strict/Lax on all "
                                    "session/authentication cookies.",
                })
                logger.finding("MEDIUM", f"Cookie '{c.name}' missing security attributes")

    return findings