"""
mock_bonus_server.py
A tiny server used ONLY to validate the JWT detection module, the API
discovery module, and login automation, in an isolated local
environment.

Endpoints:
- /login.php (GET/POST)  -> simple login form; on success sets a
                            Set-Cookie containing a vulnerable JWT
                            (alg: none, no exp, embeds a password claim)
- /swagger.json           -> exposes a minimal OpenAPI spec
- /api/v1/users           -> dummy API endpoint
"""

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

USERS = {"admin": "AdminPass123"}

LOGIN_FORM = """<html><body>
<form method="POST" action="/login.php">
    <input type="hidden" name="csrf_token" value="fixed-test-token">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
</body></html>"""


def make_vulnerable_jwt():
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "role": "admin", "password": "AdminPass123"}  # deliberately bad

    def b64url(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64url(header)}.{b64url(payload)}."


SWAGGER_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Demo API", "version": "1.0"},
    "paths": {
        "/api/v1/users": {"get": {}},
        "/api/v1/users/{id}": {"get": {}, "delete": {}},
        "/api/v1/admin/reset": {"post": {}},
    },
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "":
            body = b"<html><body>Welcome. <a href='/login.php'>Login</a></body></html>"
            self._send(200, body)
            return
        if self.path.startswith("/login.php"):
            body = LOGIN_FORM.encode()
            self._send(200, body)
            return
        if self.path == "/swagger.json":
            body = json.dumps(SWAGGER_SPEC).encode()
            self._send(200, body)
            return
        if self.path == "/api/v1/users":
            body = b'{"users": ["alice", "bob"]}'
            self._send(200, body)
            return
        self._send(404, b"Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        data = {k: v[0] for k, v in parse_qs(raw).items()}

        if self.path.startswith("/login.php"):
            username = data.get("username", "")
            password = data.get("password", "")
            if USERS.get(username) == password:
                token = make_vulnerable_jwt()
                body = b"<html><body>Welcome, logged in!</body></html>"
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", f"session={token}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                body = b"Error: invalid username or password."
                self._send(401, body)
            return

        self._send(404, b"Not Found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# if __name__ == "__main__":
#     server = ThreadingHTTPServer(("127.0.0.1", 8904), Handler)
#     print("Mock bonus-feature server running on http://127.0.0.1:8904")
#     server.serve_forever()