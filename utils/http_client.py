"""
http_client.py
Central HTTP wrapper used by every module so that timeout handling,
proxy support, custom headers/User-Agent and cookie handling are
implemented once and re-used consistently across the framework.
"""

import requests
from requests.exceptions import RequestException

DEFAULT_UA = "WebSecFramework/1.0 (+authorized-security-testing)"


class HttpClient:
    def __init__(self, timeout=10, user_agent=None, cookies=None,
                extra_headers=None, proxy=None, verify_ssl=True):
        self.timeout = timeout
        self.session = requests.Session()

        headers = {"User-Agent": user_agent or DEFAULT_UA}
        if extra_headers:
            headers.update(extra_headers)
        self.session.headers.update(headers)

        if cookies:
            # cookies passed as "k1=v1; k2=v2"
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    self.session.cookies.set(k, v)

        self.proxies = None
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}

        self.verify_ssl = verify_ssl

    def get(self, url, params=None, allow_redirects=True):
        return self._request("GET", url, params=params, allow_redirects=allow_redirects)

    def post(self, url, data=None, allow_redirects=True):
        return self._request("POST", url, data=data, allow_redirects=allow_redirects)

    def _request(self, method, url, **kwargs):
        try:
            resp = self.session.request(
                method, url,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.verify_ssl,
                **kwargs
            )
            return resp
        except RequestException as exc:
            return None if False else RequestFailure(exc)


class RequestFailure:
    """Lightweight stand-in returned when a request raises, so calling
    modules can check `resp.ok` without a try/except at every call site."""
    def __init__(self, exc):
        self.ok = False
        self.error = str(exc)
        self.status_code = None
        self.text = ""
        self.headers = {}
        self.elapsed = None
