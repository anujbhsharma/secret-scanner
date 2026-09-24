#!/usr/bin/env python3
"""secret-scanner: fail-fast leaked-secret detection for CI.

Reads configuration from GitHub Action inputs (``INPUT_*`` env vars), scans
either the full tracked file set or only changed lines, and reports findings
as ``::error`` workflow annotations plus a step summary.

Secret *values* are never printed anywhere. Annotations and summaries carry
only the file, line number, and a generic finding label.
"""

import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection rules: (rule_id, label, compiled regex). This table is the single
# source of truth for every pattern the scanner knows; both the CLI and the
# local playground UI consume it from here. Do not duplicate these regexes.
# The "Generic secret assignment" rule reports only the variable name,
# never the captured value.
# ---------------------------------------------------------------------------

RULES = [
    ("aws-access-key",
     "AWS access key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token",
     "GitHub token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-token",
     "GitHub fine-grained token",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack-token",
     "Slack token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private-key",
     "Private key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("generic-secret-assignment",
     "Generic secret assignment",
     re.compile(
         r"(?i)\b(api[_-]?key|api[_-]?secret|secret|passwd|password|pwd"
         r"|auth[_-]?token|access[_-]?token|client[_-]?secret)\b"
         r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=]{12,})['\"]?"
     )),
]

# Rule id for the entropy heuristic (not a regex rule, so it lives outside
# RULES but is still defined exactly once, here).
HIGH_ENTROPY_RULE_ID = "high-entropy-string"

# Long token-ish runs are candidates for the entropy check.
ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")

# Dependency lockfiles: full of hashes, never worth scanning.
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "pdm.lock", "Gemfile.lock", "composer.lock",
    "Cargo.lock", "go.sum",
}


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def get_input(name, default=""):
    """Read an action input. GitHub exposes ``fail-on-findings`` as
    ``INPUT_FAIL-ON-FINDINGS`` (dashes preserved); accept the underscored
    variant too for robustness."""
    upper = name.upper()
    for key in (f"INPUT_{upper}", f"INPUT_{upper.replace('-', '_')}"):
        if key in os.environ:
            return os.environ[key]
    return default


def to_bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "y")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One detected secret. ``label`` is human-readable and never contains a
    secret value; ``spans`` are (start, end) offsets of the secret *value*
    within the line so UIs can mask it."""
    rule_id: str
    label: str
    line: int = 0            # 1-based; 0 = not yet assigned
    spans: list = field(default_factory=list)
    filename: str = ""

    def masked_line(self, line_text):
        """Return the line with every secret span replaced by [redacted]."""
        out = line_text
        for start, end in sorted(set(self.spans), reverse=True):
            out = out[:start] + "[redacted]" + out[end:]
        return out


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_line(line, entropy_threshold):
    """Return a list of Finding objects for one line (line numbers unset).
    Labels never contain secret values."""
    findings = []
    for rule_id, label, pattern in RULES:
        for match in pattern.finditer(line):
            if rule_id == "generic-secret-assignment":
                var_name = match.group(1)
                # Mask only the captured value (group 2), keep the name.
                span = (match.start(2), match.end(2))
                findings.append(Finding(
                    rule_id,
                    f"Possible hardcoded secret assigned to '{var_name}'",
                    spans=[span]))
            else:
                findings.append(Finding(
                    rule_id, f"{label} detected",
                    spans=[(match.start(), match.end())]))
    # Entropy pass: skip spans already claimed by a named rule so one
    # secret is reported once, not twice.
    claimed = [span for f in findings for span in f.spans]
    for match in ENTROPY_CANDIDATE.finditer(line):
        token = match.group(0)
        if any(s < match.end() and e > match.start() for s, e in claimed):
            continue
        if shannon_entropy(token) >= entropy_threshold:
            findings.append(Finding(
                HIGH_ENTROPY_RULE_ID,
                "High-entropy string (possible secret)",
                spans=[(match.start(), match.end())]))
            claimed.append((match.start(), match.end()))
    return findings


def find_secrets(text, filename="", entropy_threshold=4.5, exclude=()):
    """Scan raw text and return a list of Finding with 1-based line numbers.

    Honors the same skip rules as the CLI: files under an ``exclude``
    prefix and dependency lockfiles are not scanned.
    """
    if filename:
        rel = filename.strip().lstrip("./")
        if excluded(rel, exclude) or is_lockfile(rel):
            return []
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for finding in scan_line(line, entropy_threshold):
            finding.line = lineno
            finding.filename = filename
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def excluded(relpath, prefixes):
    return any(relpath == p or relpath.startswith(p + "/") for p in prefixes)


def is_lockfile(relpath):
    return Path(relpath).name in LOCKFILES


def git_ok(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True)
    return result


def git_changed_lines(repo, base):
    """Map of relpath -> set of changed (1-based) line numbers in the new
    version, parsed from ``git diff -U0``. Returns None if the diff fails."""
    result = git_ok(repo, "diff", "-U0", base, "HEAD", "--")
    if result.returncode != 0:
        return None
    changed = {}
    current = None
    new_line = 0
    for line in result.stdout.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            if path.startswith("b/"):
                path = path[2:]
            current = None if path == "/dev/null" else path
            if current is not None:
                changed.setdefault(current, set())
        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            new_line = int(m.group(1)) if m else 0
        elif current is not None:
            if line.startswith("+") and not line.startswith("+++"):
                changed[current].add(new_line)
                new_line += 1
            elif line.startswith("-") and not line.startswith("---"):
                pass  # removed line: new-side counter unchanged
            else:
                new_line += 1  # context line (none expected with -U0)
    return changed


def git_tracked(repo):
    result = git_ok(repo, "ls-files")
    if result.returncode != 0:
        return None
    return [l for l in result.stdout.splitlines() if l]


def git_untracked(repo):
    result = git_ok(repo, "ls-files", "--others", "--exclude-standard")
    if result.returncode != 0:
        return []
    return [l for l in result.stdout.splitlines() if l]


def walk_files(repo):
    files = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo).as_posix()
        if rel.startswith(".git/"):
            continue
        files.append(rel)
    return files


def collect_targets(repo, only_diff, base, prefixes):
    """Return [(relpath, lines_or_None)]; lines None means the whole file."""
    tracked = git_tracked(repo)
    if tracked is None:
        # Not a git repo: scan the working tree.
        return [(r, None) for r in walk_files(repo)
                if not excluded(r, prefixes) and not is_lockfile(r)]
    if only_diff and base and not re.fullmatch(r"0+", base or ""):
        changed = git_changed_lines(repo, base)
        if changed is not None:
            targets = [(r, lines) for r, lines in changed.items()
                       if lines and not excluded(r, prefixes)
                       and not is_lockfile(r)]
            targets += [(r, None) for r in git_untracked(repo)
                        if not excluded(r, prefixes) and not is_lockfile(r)]
            return targets
        # Diff failed (bad base ref): fall through to a full scan.
    return [(r, None) for r in tracked
            if not excluded(r, prefixes) and not is_lockfile(r)]


def read_lines(repo, relpath):
    path = repo / relpath
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in data[:8192]:
        return []  # binary file: skip
    return data.decode("utf-8", errors="replace").splitlines()


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def emit_annotations(findings):
    for relpath, lineno, label in findings:
        # The label never contains a secret value.
        print(f"::error file={relpath},line={lineno}::{label} (secret value redacted)")


def write_summary(findings):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("## Secret scan results\n\n")
        if not findings:
            fh.write("No secrets detected.\n")
            return
        fh.write(f"**{len(findings)}** potential secret(s) found:\n\n")
        fh.write("| File | Line | Finding |\n| --- | --- | --- |\n")
        for relpath, lineno, label in findings:
            fh.write(f"| `{relpath}` | {lineno} | {label} |\n")


def write_output(findings):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"findings={len(findings)}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    fail_on_findings = to_bool(get_input("fail-on-findings", "true"))
    prefixes = [p.strip().rstrip("/")
                for p in get_input("exclude", "").split(",") if p.strip()]
    only_diff = to_bool(get_input("only-diff", "true"))
    try:
        entropy_threshold = float(get_input("entropy-threshold", "4.5"))
    except ValueError:
        entropy_threshold = 4.5
    base = os.environ.get("SCAN_BASE_SHA", "").strip()
    repo = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd()))

    findings = []
    for relpath, lines in collect_targets(repo, only_diff, base, prefixes):
        for lineno, line in enumerate(read_lines(repo, relpath), start=1):
            if lines is not None and lineno not in lines:
                continue
            for finding in scan_line(line, entropy_threshold):
                findings.append((relpath, lineno, finding.label))

    emit_annotations(findings)
    write_summary(findings)
    write_output(findings)

    if findings and fail_on_findings:
        print(f"::error::Secret scan failed: {len(findings)} finding(s). "
              f"(Values redacted.)")
        return 1
    print(f"Secret scan complete: {len(findings)} finding(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
