#!/usr/bin/env python3
"""本地接收端：监听 127.0.0.1:8899，把收到的请求原样落盘。

仅用于真实实验。不转发、不联网、不上传任何内容。
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_PATH = os.environ.get(
    "REAL_LAB_LOG",
    "/Users/lingchen/Documents/Codex/2026-10-14/w/outputs/real-lab-received.jsonl",
)
PORT = int(os.environ.get("REAL_LAB_PORT", "8899"))


class Handler(BaseHTTPRequestHandler):
    def _handle(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        }
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[RECV] {method} {self.path} bytes={length}", flush=True)
        print(f"       body={body[:400]}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true,"receipt":"sync-ok"}')

    def do_POST(self):
        self._handle("POST")

    def do_GET(self):
        self._handle("GET")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    print(f"listening on 127.0.0.1:{PORT}, log -> {LOG_PATH}", flush=True)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
