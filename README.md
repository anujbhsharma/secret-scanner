# secret-scanner

[![Live demo](https://img.shields.io/badge/demo-live-brightgreen)](https://anujbhsharma.github.io/secret-scanner/)

**[Try the live demo](https://anujbhsharma.github.io/secret-scanner/)** — the real
`scan.py` detection engine running in your browser via Pyodide. No install needed.

A GitHub Action that reads your diffs so your secrets don't end up in everyone
else's. It scans pushes and pull requests for leaked API keys, tokens, and
private keys — and fails the workflow when it finds them, before the damage
is done.

No dependencies. One Python file. Zero excuses for committing `AKIA...` again.

## Usage

```yaml
name: Secrets check

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required: the scanner diffs against the base ref
      - uses: anujbhsharma/secret-scanner@v1
```

> **Note:** `fetch-depth: 0` matters. With a shallow clone the action can't see
> the base commit, so it falls back to scanning every tracked file — slower,
> noisier, and not what you want on every PR.

## Inputs

| Input              | Default | Description                                                        |
| ------------------ | ------- | ------------------------------------------------------------------ |
| `fail-on-findings` | `true`  | Fail the workflow when secrets are found                           |
| `exclude`          | `''`    | Comma-separated path prefixes to skip (e.g. `"tests/,docs/"`)      |
| `only-diff`        | `true`  | Scan only changed lines vs the base ref; `false` scans everything |
| `entropy-threshold`| `4.5`   | Shannon entropy cutoff for unknown-token detection (lower = keener)|

## Outputs

| Output     | Description                  |
| ---------- | ---------------------------- |
| `findings` | Number of secret findings    |

## What it detects

| Finding                    | Example                                             |
| -------------------------- | --------------------------------------------------- |
| AWS access key             | `AKIAIOSFODNN7EXAMPLE`                              |
| GitHub token               | `ghp_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`          |
| GitHub fine-grained token  | `github_pat_…`                                      |
| Slack token                | `xoxb-…`, `xoxp-…`, `xoxa-…`, `xoxr-…`, `xoxs-…`     |
| Private key                | `-----BEGIN RSA PRIVATE KEY-----` (EC/DSA/OpenSSH too) |
| Generic secret assignment  | `api_key = "…"`, `password: "…"`, `client_secret=…` |
| High-entropy string        | Any 20+ char token-ish run above the entropy cutoff |

It also skips dependency lockfiles (`package-lock.json`, `yarn.lock`,
`poetry.lock`, `Cargo.lock`, `go.sum`, …) — those are hash soup, not secrets —
and binary files.

## Your secrets stay secret

This is the important part: **the scanner never prints a matched value.**
Workflow annotations carry only the file, line number, and a generic label:

```
::error file=src/config.py,line=12::Possible hardcoded secret assigned to 'api_key' (secret value redacted)
```

The step summary lists counts and locations. The values themselves go nowhere —
not to logs, not to summaries, not to annotations.

## Tuning the entropy detector

The entropy check catches the weird stuff — tokens from providers nobody wrote
a regex for. It flags any 20+ character alphanumeric run whose Shannon entropy
meets `entropy-threshold` (default `4.5`).

- Getting noise from long identifiers or hashes in non-lockfile files? Raise it
  toward `5.0`.
- Hunting stealthier leaks and willing to triage? Lower it toward `4.0`.
- Spans already claimed by a named pattern are never double-counted.

No detector is perfect. This one would rather tap you on the shoulder about a
suspicious string than wave through a real key — tune the threshold to your
team's tolerance, and `exclude` the paths that cry wolf (looking at you,
`tests/fixtures/`).

## Try it locally

Want to poke the scanner without committing anything? There's a playground:

```bash
python ui.py            # or: python ui.py --port 8000
```

Then open http://127.0.0.1:8000 — a single page (stdlib only, no build step,
no CDN) where you can paste code, load the leaky/clean examples, tweak the
exclude prefixes and entropy threshold, and see findings highlighted on
redacted lines. It runs the exact same `scan.py` engine as the action, so
what you see is what CI would flag. Nothing leaves your machine, and secret
values are never displayed — not even to you.

## Local development

```bash
python -m pytest tests/ -v
```

The suite builds throwaway git repos, plants fake secrets from
`tests/fixtures/`, and runs `scan.py` exactly the way the action does —
including diff-only mode, exclusions, lockfile skipping, and a strict
"no secret value may appear in output" assertion. `tests/test_ui.py` spins up
the playground server on an ephemeral port and asserts the API returns the
same findings as the CLI, with the same redaction guarantees.

## License

MIT — see [LICENSE](LICENSE).
