"""Tiny OpenAI-compatible HTTP stub for tests. The real client calls this."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def start_openai_stub(
    verdict: str = "suspicious",
    reason: str = "stub triage",
    confidence: float = 0.66,
    raw_content: str | None = None,
):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            if length:
                self.rfile.read(length)
            if not str(self.path).endswith("/chat/completions"):
                self.send_response(404)
                self.end_headers()
                return
            content = raw_content if raw_content is not None else json.dumps(
                {"verdict": verdict, "confidence": confidence, "reasons": [reason]}
            )
            body = json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    return httpd, f"http://127.0.0.1:{port}/v1"


def stop_openai_stub(httpd: HTTPServer) -> None:
    httpd.shutdown()
    httpd.server_close()
