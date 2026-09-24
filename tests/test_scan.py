"""Tests for scan.py. Each test builds a throwaway git repo, plants the
fixture files, and runs the scanner as a subprocess exactly the way the
GitHub Action would (INPUT_* env vars, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY).
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCAN_PY = Path(__file__).resolve().parent.parent / "scan.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# The fake secret *values* planted in leaky.txt. None of these may ever
# appear in the scanner's stdout, annotations, or step summary.
PLANTED_VALUES = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrSt",
    "supersecretapikey12345",
    "aB3dE9fG2hJ7kL4mN8pQ1rS6tU0vW5xY",
]


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args],
                   check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "test@example.com")
    git(r, "config", "user.name", "test")
    return r


def commit_all(repo, message):
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", message)


def plant(repo, *names):
    for name in names:
        shutil.copy(FIXTURES / Path(name).name, repo / name)


def run_scan(repo, tmp_path, **inputs):
    # scan.py appends to these files; start fresh so counts don't go stale
    for stale in ("github_output", "step_summary.md"):
        p = tmp_path / stale
        if p.exists():
            p.unlink()
    env = dict(os.environ)
    env.update({
        "GITHUB_WORKSPACE": str(repo),
        "INPUT_FAIL-ON-FINDINGS": "true",
        "INPUT_EXCLUDE": "",
        "INPUT_ONLY-DIFF": "false",
        "INPUT_ENTROPY-THRESHOLD": "4.5",
        "GITHUB_OUTPUT": str(tmp_path / "github_output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "step_summary.md"),
    })
    for key, value in inputs.items():
        env["INPUT_" + key.upper().replace("-", "_")] = value
        # also set the dashed variant, mirroring the composite action
        env["INPUT_" + key.upper()] = value
    proc = subprocess.run([sys.executable, str(SCAN_PY)],
                          cwd=str(repo), env=env,
                          capture_output=True, text=True)
    count = None
    out_file = tmp_path / "github_output"
    if out_file.exists():
        m = re.search(r"^findings=(\d+)$",
                      out_file.read_text(), re.MULTILINE)
        count = int(m.group(1)) if m else None
    return proc, count


def assert_no_values_leaked(text):
    for value in PLANTED_VALUES:
        assert value not in text, f"secret value leaked into output: {value[:8]}..."


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_detects_all_planted_secret_types(repo, tmp_path):
    """leaky.txt holds 6 planted secret types; expect exactly 6 findings."""
    plant(repo, "leaky.txt")
    commit_all(repo, "add leaky fixture")
    proc, count = run_scan(repo, tmp_path)
    assert proc.returncode == 1  # fail-on-findings defaults to true
    assert count == 6
    assert_no_values_leaked(proc.stdout)
    # annotations reference file and line, never the value
    assert "::error file=leaky.txt,line=" in proc.stdout


def test_clean_file_has_no_findings(repo, tmp_path):
    plant(repo, "clean.py")
    commit_all(repo, "add clean fixture")
    proc, count = run_scan(repo, tmp_path)
    assert proc.returncode == 0
    assert count == 0


def test_exclude_prefix_skips_matches(repo, tmp_path):
    (repo / "fixtures").mkdir()
    plant(repo, "fixtures/leaky.txt")
    commit_all(repo, "add leaky fixture under fixtures/")
    proc, count = run_scan(repo, tmp_path, exclude="fixtures")
    assert proc.returncode == 0
    assert count == 0


def test_only_diff_scans_changed_lines(repo, tmp_path):
    # Scenario A: the leaky file is introduced in the second commit, so the
    # diff (base = first commit) must catch all 6 findings.
    plant(repo, "clean.py")
    commit_all(repo, "clean first")
    plant(repo, "leaky.txt")
    commit_all(repo, "leaky second")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD~1"],
                          check=True, capture_output=True,
                          text=True).stdout.strip()
    env_base = {"SCAN_BASE_SHA": base}
    old = dict(os.environ)
    os.environ.update(env_base)
    try:
        proc, count = run_scan(repo, tmp_path, **{"only-diff": "true"})
    finally:
        os.environ.clear()
        os.environ.update(old)
    assert count == 6
    assert proc.returncode == 1


def test_only_diff_ignores_unchanged_files(repo, tmp_path):
    # Scenario B: leaky.txt is committed first, then only clean.py changes.
    # Diff mode must report nothing; full mode must still find all 6.
    plant(repo, "leaky.txt")
    commit_all(repo, "leaky first")
    plant(repo, "clean.py")
    commit_all(repo, "clean second")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD~1"],
                          check=True, capture_output=True,
                          text=True).stdout.strip()
    old = dict(os.environ)
    os.environ["SCAN_BASE_SHA"] = base
    try:
        proc, count = run_scan(repo, tmp_path, **{"only-diff": "true"})
        assert count == 0
        assert proc.returncode == 0
        proc, count = run_scan(repo, tmp_path, **{"only-diff": "false"})
        assert count == 6
    finally:
        os.environ.clear()
        os.environ.update(old)


def test_fail_on_findings_false_exits_zero(repo, tmp_path):
    plant(repo, "leaky.txt")
    commit_all(repo, "add leaky fixture")
    proc, count = run_scan(repo, tmp_path, **{"fail-on-findings": "false"})
    assert proc.returncode == 0
    assert count == 6  # still reported, just not fatal


def test_lockfiles_are_skipped(repo, tmp_path):
    (repo / "package-lock.json").write_text(
        '{ "token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789" }\n')
    commit_all(repo, "add lockfile with fake token")
    proc, count = run_scan(repo, tmp_path)
    assert count == 0
    assert proc.returncode == 0


def test_step_summary_redacts_values(repo, tmp_path):
    plant(repo, "leaky.txt")
    commit_all(repo, "add leaky fixture")
    proc, count = run_scan(repo, tmp_path)
    summary = (tmp_path / "step_summary.md").read_text()
    assert_no_values_leaked(summary)
    assert "6" in summary  # the count is reported, values are not
