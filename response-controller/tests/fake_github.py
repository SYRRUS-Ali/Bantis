import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "github_pat_TESTONLY0123456789abcdef"


class FakeGitHub:
    def __init__(self, repo="SYRRUS-Ali/Bantis"):
        self.repo = repo
        self.variables: dict[str, str] = {}
        self.requests: list[tuple[str, str]] = []
        self.fail: dict[str, int] = {}  # method -> status to return instead
        self.drop_writes = False  # accept a create, then lose it (for post-check tests)
        self.drop_deletes = False  # accept a delete, but the variable stays
        self.on_get = None  # hook run before answering a GET
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, body=None):
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self, method):
                fake.requests.append((method, self.path))
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"message": "Bad credentials"})
                if method in fake.fail:
                    return self._send(fake.fail[method], {"message": "Resource not accessible by integration"})
                prefix = f"/repos/{fake.repo}/actions/variables"
                if not self.path.startswith(prefix):
                    return self._send(404, {"message": "Not Found"})
                name = self.path[len(prefix):].lstrip("/")
                if method == "GET":
                    if fake.on_get:
                        fake.on_get()
                    if name in fake.variables:
                        return self._send(200, {"name": name, "value": fake.variables[name]})
                    return self._send(404, {"message": "Not Found"})
                if method == "POST":
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    if body["name"] in fake.variables:
                        return self._send(409, {"message": "Already exists"})
                    if not fake.drop_writes:
                        fake.variables[body["name"]] = body["value"]
                    return self._send(201, {})
                if method == "DELETE":
                    if name not in fake.variables:
                        return self._send(404, {"message": "Not Found"})
                    if not fake.drop_deletes:
                        del fake.variables[name]
                    return self._send(204)
                return self._send(405, {"message": "no"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_DELETE(self):
                self._handle("DELETE")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def writes(self):
        return [r for r in self.requests if r[0] != "GET"]

    def close(self):
        self.server.shutdown()
        self.server.server_close()