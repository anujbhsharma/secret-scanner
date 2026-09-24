#!/usr/bin/env python3
"""secret-scanner playground: a tiny local web UI for trying the scanner.

Runs a stdlib-only HTTP server (no dependencies, no build step, no CDN)
serving a single-page playground at ``/`` and a JSON API at ``/api/scan``.

Usage:
    python ui.py [--port 8000]

All detection logic lives in scan.py; this file only serves HTTP and
renders results. Secret values are never included in any response.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import scan  # the detection engine; patterns live there, never here

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
FIXTURES_DIR = ROOT / "tests" / "fixtures"

# Hard cap on pasted text: the playground is local, but a runaway paste
# should not balloon memory.
MAX_BODY_BYTES = 1_000_000
MAX_TEXT_CHARS = 200_000

EXAMPLES = {
    "leaky": ("leaky.txt", "Deliberately leaky fixture (6 planted fakes)"),
    "clean": ("clean.py", "Clean example config (no findings expected)"),
}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_payload(data):
    """Validate a /api/scan body and return the JSON-serializable result."""
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    text = data.get("text", "")
    if not isinstance(text, str):
        raise ValueError("'text' must be a string")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"'text' exceeds {MAX_TEXT_CHARS} characters")
    filename = data.get("filename") or "pasted.txt"
    if not isinstance(filename, str):
        raise ValueError("'filename' must be a string")

    raw_exclude = data.get("exclude", "")
    if isinstance(raw_exclude, str):
        exclude = [p.strip().rstrip("/")
                   for p in raw_exclude.split(",") if p.strip()]
    elif isinstance(raw_exclude, list):
        exclude = [str(p).strip().rstrip("/")
                   for p in raw_exclude if str(p).strip()]
    else:
        raise ValueError("'exclude' must be a string or a list of strings")

    try:
        threshold = float(data.get("entropy_threshold", 4.5))
    except (TypeError, ValueError):
        raise ValueError("'entropy_threshold' must be a number")
    if not 0 < threshold < 10:
        raise ValueError("'entropy_threshold' must be between 0 and 10")

    findings = scan.find_secrets(
        text, filename=filename,
        entropy_threshold=threshold, exclude=tuple(exclude))

    by_line = {}
    for f in findings:
        by_line.setdefault(f.line, []).append(f)

    lines = []
    for n, raw in enumerate(text.splitlines(), start=1):
        line_findings = by_line.get(n, [])
        masked = raw
        if line_findings:
            spans = sorted({s for f in line_findings for s in f.spans},
                           reverse=True)
            for start, end in spans:
                masked = masked[:start] + "[redacted]" + masked[end:]
        lines.append({"n": n, "text": masked,
                      "has_finding": bool(line_findings)})

    by_rule = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

    return {
        "findings": [
            {"rule_id": f.rule_id, "line": f.line,
             "preview_redacted": f.label}
            for f in findings
        ],
        "summary": {"count": len(findings), "by_rule": by_rule},
        # Rendered text with every secret value masked; the UI highlights
        # has_finding lines. Raw secret values never leave the server.
        "lines": lines,
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "secret-scanner-playground/1.0"

    def _send(self, status, body, content_type="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, obj):
        self._send(status, json.dumps(obj))

    def _error(self, status, message):
        self._send_json(status, {"error": message})

    # -- routing ---------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_file(STATIC_DIR / "index.html", "text/html")
        elif parsed.path == "/api/example":
            self._serve_example(parse_qs(parsed.query))
        elif parsed.path.startswith("/static/"):
            name = parsed.path[len("/static/"):]
            if ".." in name or "/" in name:
                self._error(404, "not found")
            else:
                self._serve_file(STATIC_DIR / name, "text/plain")
        else:
            self._error(404, "not found")

    def do_POST(self):
        if urlparse(self.path).path != "/api/scan":
            self._error(404, "not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY_BYTES:
            self._error(413, "request body too large")
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, ValueError):
            self._error(400, "request body must be valid JSON")
            return
        try:
            self._send_json(200, scan_payload(data))
        except ValueError as exc:
            # Validation errors only; never a traceback, never a secret.
            self._error(400, str(exc))
        except Exception:  # pragma: no cover - defensive
            self._error(500, "internal error while scanning")

    # -- helpers ----------------------------------------------------------

    def _serve_file(self, path, content_type):
        try:
            body = path.read_bytes()
        except OSError:
            self._error(404, "not found")
            return
        self._send(200, body, content_type)

    def _serve_example(self, query):
        name = (query.get("name") or [""])[0]
        if name not in EXAMPLES:
            self._error(400, "unknown example; use ?name=leaky or ?name=clean")
            return
        filename, description = EXAMPLES[name]
        try:
            text = (FIXTURES_DIR / filename).read_text(encoding="utf-8")
        except OSError:
            self._error(500, "example fixture missing")
            return
        # This endpoint fills the user's own textarea (their input, editable).
        # Scan *results* never echo secret values back.
        self._send_json(200, {"name": name, "filename": filename,
                              "description": description, "text": text})

    def log_message(self, fmt, *args):  # quieter logs
        sys.stderr.write("playground: " + fmt % args + "\n")


def make_server(host="127.0.0.1", port=8000):
    """Create (but do not start) the playground server."""
    return ThreadingHTTPServer((host, port), Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local playground UI for secret-scanner.")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)

    server = make_server(args.host, args.port)
    url = f"http://{args.host}:{server.server_address[1]}/"
    print(f"secret-scanner playground running at {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
