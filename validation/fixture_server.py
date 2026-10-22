#!/usr/bin/env python3
"""Restricted-environment visual validation server.

Serves the exact embedded production HTML and returns the deterministic analysis
fixture for POST /api/analyze. It is not a substitute for TShark validation and
is clearly recorded as such in VALIDATION_REPORT.md.
"""
from __future__ import annotations

import ast
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "pcap_insight.py"
FIXTURE = ROOT / "validation" / "synthetic_analysis_fixture.json"


def embedded_html() -> bytes:
    tree = ast.parse(SOURCE.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HTML" for t in n.targets))
    html = ast.literal_eval(node.value)
    version = re.search(r'^APP_VERSION = "([^"]+)"', SOURCE.read_text(), re.M).group(1)
    return html.replace("{{ version }}", version).replace("{{ max_mb }}", "512").encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path in {"/", "/index.html"}:
            body = embedded_html(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path == "/api/health":
            version = re.search(r'^APP_VERSION = "([^"]+)"', SOURCE.read_text(), re.M).group(1)
            body = json.dumps({"status": "validation-fixture", "version": version, "tshark": False}).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body); return
        self.send_error(404)

    def do_POST(self):
        if self.path != "/api/analyze": self.send_error(404); return
        size = int(self.headers.get("Content-Length", "0")); self.rfile.read(size)
        body = FIXTURE.read_bytes(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--port", type=int, default=8877); args = parser.parse_args()
    print(f"Validation fixture server: http://127.0.0.1:{args.port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
