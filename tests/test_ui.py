"""Tests for ui.py (the local playground server).

Spins up the stdlib HTTP server on an ephemeral port in a thread and
exercises the JSON API. Detection expectations mirror the CLI tests in
test_scan.py: the leaky fixture must yield exactly the same 6 findings.
"""

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
sys.path.insert(0, str(REPO))

EXPECTED_FINDINGS = [
    (2, "aws-access-key"),
    (3, "github-token"),
    (4, "slack-token"),
    (5, "generic-secret-assignment"),
    (6, "private-key"),
    (7, "high-entropy-string"),
]


def planted_values():
    """Extract the fake secret *values* from leaky.txt programmatically so
    the test never hardcodes them (and can never leak them into a diff)."""
    values = []
    for raw in (FIXTURES / "leaky.txt").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-----"):
            values.append(line)  # key header must never be echoed either
            continue
        if "=" in line:
            v = line.split("=", 1)[1].strip().strip('"').strip("'")
            if v:
                values.append(v)
        else:
            values.append(line)  # standalone token line
    return values


@pytest.fixture(scope="module")
def base_url():
    import ui
    server = ui.make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def get(base_url, path):
    try:
        with urllib.request.urlopen(base_url + path) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def post(base_url, path, payload, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        base_url + path, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def post_json(base_url, payload):
    status, body = post(base_url, "/api/scan", payload)
    return status, json.loads(body), body


# ---------------------------------------------------------------------------
# API behavior
# ---------------------------------------------------------------------------

def test_scan_leaky_fixture_matches_cli(base_url):
    """Same 6 findings, same lines, same rule ids as the CLI test."""
    text = (FIXTURES / "leaky.txt").read_text()
    status, data, _ = post_json(base_url, {"text": text,
                                           "filename": "leaky.txt"})
    assert status == 200
    assert data["summary"]["count"] == 6
    got = sorted((f["line"], f["rule_id"]) for f in data["findings"])
    assert got == EXPECTED_FINDINGS
    assert data["summary"]["by_rule"] == {r: 1 for _, r in EXPECTED_FINDINGS}
    hit_lines = [l for l in data["lines"] if l["has_finding"]]
    assert len(hit_lines) == 6
    assert all("[redacted]" in l["text"] for l in hit_lines)


def test_scan_never_echoes_secret_values(base_url):
    """No planted value may appear anywhere in the API response."""
    text = (FIXTURES / "leaky.txt").read_text()
    status, data, raw = post_json(base_url, {"text": text,
                                             "filename": "leaky.txt"})
    assert status == 200
    for value in planted_values():
        assert len(value) >= 8
        assert value not in raw, f"secret value echoed in response: {value[:8]}..."
    # belt and suspenders: check the structured fields too
    blob = json.dumps(data)
    for value in planted_values():
        assert value not in blob


def test_clean_example_has_no_findings(base_url):
    text = (FIXTURES / "clean.py").read_text()
    status, data, _ = post_json(base_url, {"text": text,
                                           "filename": "clean.py"})
    assert status == 200
    assert data["summary"]["count"] == 0
    assert data["findings"] == []


def test_exclude_prefix_respected(base_url):
    text = (FIXTURES / "leaky.txt").read_text()
    status, data, _ = post_json(base_url, {"text": text,
                                           "filename": "vendor/leaky.txt",
                                           "exclude": "vendor"})
    assert status == 200
    assert data["summary"]["count"] == 0


def test_example_endpoints(base_url):
    status, body = get(base_url, "/api/example?name=leaky")
    assert status == 200
    data = json.loads(body)
    assert data["filename"] == "leaky.txt"
    assert "aws_access_key_id" in data["text"]

    status, body = get(base_url, "/api/example?name=clean")
    assert status == 200
    assert json.loads(body)["filename"] == "clean.py"

    status, body = get(base_url, "/api/example?name=bogus")
    assert status == 400
    assert "error" in json.loads(body)


def test_index_page_served(base_url):
    status, body = get(base_url, "/")
    assert status == 200
    assert "secret-scanner playground" in body


def test_invalid_requests_get_clean_errors(base_url):
    # not JSON at all
    status, body = post(base_url, "/api/scan", None, raw=b"{nope")
    assert status == 400
    assert "error" in json.loads(body)

    # wrong types
    for payload in ({"text": 123},
                    {"text": "x", "entropy_threshold": "banana"},
                    {"text": "x", "exclude": 42},
                    ["not", "an", "object"]):
        status, body = post(base_url, "/api/scan", payload)
        assert status == 400, payload
        assert "error" in json.loads(body)

    # no tracebacks, ever
    assert "Traceback" not in body

    # unknown routes
    status, _ = get(base_url, "/api/scan")
    assert status == 404
    status, _ = get(base_url, "/nope")
    assert status == 404


# ---------------------------------------------------------------------------
# No duplicated detection logic
# ---------------------------------------------------------------------------

def test_patterns_defined_once():
    """The pattern table must live in exactly one place: scan.py."""
    import scan
    import ui

    # ui.py must not define (or re-export) any detection patterns
    ui_src = (REPO / "ui.py").read_text()
    assert "re.compile" not in ui_src
    assert not hasattr(ui, "RULES")
    assert not hasattr(ui, "PATTERNS")

    # the regex literals live in scan.py and nowhere else (excluding tests)
    holders = [p.name for p in REPO.glob("*.py") if "AKIA" in p.read_text()]
    assert holders == ["scan.py"]

    # the served page carries no patterns either
    html = (REPO / "static" / "index.html").read_text()
    assert "AKIA" not in html
    assert "xoxb" not in html

    # ...and both entry points consume the same table object
    assert ui.scan.RULES is scan.RULES
