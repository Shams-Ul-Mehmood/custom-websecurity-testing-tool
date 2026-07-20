"""
mock_echo_server.py
A tiny server used ONLY to verify that the framework's HTTP client
correctly transmits custom User-Agent, cookies, and custom headers,
and to simulate a slow endpoint for timeout-handling verification.

    - /echo    -> returns the received headers/cookies as JSON
    - /slow    -> sleeps 6s before responding (used to test --timeout)
"""

import json
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/slow":
            time.sleep(6)
            self._send(200, b"slow response")
            return

        if parsed.path == "/delay":
            qs = parse_qs(parsed.query)
            seconds = float(qs.get("seconds", ["2"])[0])
            time.sleep(seconds)
            self._send(200, f"delayed {seconds}s".encode())
            return

        if parsed.path == "/echo":
            data = {
                "user_agent": self.headers.get("User-Agent", ""),
                "cookie": self.headers.get("Cookie", ""),
                "x_custom_header": self.headers.get("X-Custom-Header", ""),
                "x_test_flag": self.headers.get("X-Test-Flag", ""),
            }
            body = json.dumps(data).encode()
            self._send(200, body)
            return

        self._send(404, b"Not Found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
