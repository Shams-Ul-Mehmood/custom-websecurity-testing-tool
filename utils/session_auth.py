"""
session_auth.py
Session management + login automation.

Given login credentials, performs a best-effort automated login against
a target's login form and leaves the resulting session (cookies) on the
shared HttpClient's requests.Session, so every subsequent module call
(headers, xss, sqli, jwt, api, ...) automatically operates as an
authenticated user without any extra wiring.

Non-destructive: only ever submits the credentials explicitly supplied
by the operator via --login-user/--login-pass; never guesses or brute
forces credentials.
"""

import re

HIDDEN_INPUT_RE = re.compile(
    r'<input[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
NAME_ATTR_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
VALUE_ATTR_RE = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)

FAILURE_KEYWORDS = ["invalid", "incorrect", "error", "denied", "failed",
                    "not found", "try again", "unauthorized"]


def perform_login(client, login_url, username, password,
                username_field="username", password_field="password"):
    """Attempts an automated login. Returns (success: bool, detail: str).

    Best-effort CSRF handling: any hidden <input> fields on the login
    page are collected and included in the POST body unchanged, since
    many frameworks require the exact CSRF token value round-tripped.
    """
    pre_resp = client.get(login_url)
    if pre_resp is None or not hasattr(pre_resp, "text"):
        return False, f"Login page unreachable: {getattr(pre_resp, 'error', 'no response')}"

    baseline_cookies = dict(client.session.cookies)
    baseline_status = getattr(pre_resp, "status_code", None)

    form_data = {username_field: username, password_field: password}
    for tag in HIDDEN_INPUT_RE.findall(pre_resp.text or ""):
        name_match = NAME_ATTR_RE.search(tag)
        value_match = VALUE_ATTR_RE.search(tag)
        if name_match:
            form_data.setdefault(name_match.group(1), value_match.group(1) if value_match else "")

    post_resp = client.post(login_url, data=form_data, allow_redirects=False)
    if post_resp is None or not hasattr(post_resp, "status_code"):
        return False, f"Login request failed: {getattr(post_resp, 'error', 'no response')}"

    body_lower = (post_resp.text or "").lower()
    has_failure_keyword = any(kw in body_lower for kw in FAILURE_KEYWORDS)
    cookies_changed = dict(client.session.cookies) != baseline_cookies
    is_redirect = post_resp.status_code in (301, 302, 303, 307, 308)

    success = (is_redirect or post_resp.status_code == 200) and cookies_changed and not has_failure_keyword

    if success:
        return True, (f"Login appears successful (status={post_resp.status_code}, "
                    f"session cookie(s) established: {list(client.session.cookies.keys())}).")
    else:
        reason_bits = []
        if has_failure_keyword:
            reason_bits.append("failure keyword found in response")
        if not cookies_changed:
            reason_bits.append("no new session cookie set")
        if not (is_redirect or post_resp.status_code == 200):
            reason_bits.append(f"unexpected status {post_resp.status_code}")
        return False, f"Login likely failed ({'; '.join(reason_bits) or 'unknown reason'})."