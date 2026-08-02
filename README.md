# acceptance-gate

"Did the agent move the goalposts?"

Independently checks an AI-assisted code change: did the acceptance tests get
weakened/deleted alongside the fix, and does a clean, untrusted checkout of the
"after" state actually pass? Repo-agnostic, agent-agnostic — needs only a git
repo, two commits, and a test command.

## Usage

    python3 gate.py --repo <path> --before <sha> --after <sha> --test "<test command>"

## What it checks (v0)

1. **Acceptance-boundary diff** — classifies test/spec file changes:
   assertion removed, assertion/expected-value changed, skip-marker added,
   or `NEEDS_HUMAN_READ` (honest fallback, not a guess).
2. **Clean replay** — runs the test command fresh, in a disposable clone of
   the "after" commit. Never trusts the working tree or the agent's own claim.
3. Emits a fixed adversarial-review prompt (diff + boundary changes + replay
   result) — paste into any second AI as an independent reviewer. No API
   integration needed for v0.

## What it does NOT do (v0, honestly)

No cryptographic signing, no SOC2/SIEM export, no hosted service, no
multi-agent orchestration. Those are deliberately out of scope until there's
real demand.

## Try it yourself

**Prerequisites:**
- Linux with `bwrap` (bubblewrap) on PATH — used to sandbox the test replay.
- Python 3 with `venv`.
- Network access to a Python package index, **only** to install
  `requirements.txt` (currently just `jsonschema==4.19.2`). The gate replay
  step itself runs inside the bubblewrap sandbox with network disabled —
  see `sandbox.py` policy output below.

```
git clone https://github.com/osmanvarolus-art/agent-release-gate.git
cd agent-release-gate
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
git clone pilot_fixture/repo.bundle pilot_fixture/repo

# Case 1 — a real, honest fix. Expect verdict PASS.
.venv/bin/python3 gate.py --repo pilot_fixture/repo \
  --before bc2657e087389db825652f5e8e0b7de94e4d90fd \
  --after  01491aa0feaa20f8d8b0861f00e507df74ab6059 \
  --test "python3 -m unittest discover -s tests" --skip-causality

# Case 2 — code left buggy, but the failing test was weakened instead of
# fixing the code. Expect verdict REVIEW_REQUIRED, acceptance_boundary
# findings=[ASSERTION_REMOVED], unauthorized_acceptance_mutation=true.
.venv/bin/python3 gate.py --repo pilot_fixture/repo \
  --before bc2657e087389db825652f5e8e0b7de94e4d90fd \
  --after  7c6d38dfda3791fc33151bb7c36d9e8a8fbf6384 \
  --test "python3 -m unittest discover -s tests" --skip-causality
```

See `.github/workflows/stranger-ready.yml` for a manually-dispatchable CI
job that reproduces both cases from a fresh clone in an ephemeral
GitHub-hosted runner.

Both runs execute the "after" commit's tests inside a bubblewrap sandbox:
disabled network, minimal fresh `/proc`/`/dev`, read-only source mount,
disposable writable output dir, cleared environment (allowlist only), and
explicit deny-list assertions on sensitive host paths. See `sandbox.py` /
`SOURCE_PROVENANCE.json` for exact commit provenance of every published file.

The commit history in `pilot_fixture/repo.bundle` is a freshly generated
throwaway fixture created for this public release (not extracted from any
private repository's git history) — see `SOURCE_PROVENANCE.json`.
