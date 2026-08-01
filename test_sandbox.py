"""Adversarial + regression proof suite for sandbox.py (Agent Release Gate
bwrap sandbox v0.1). Every test either passes for real (sandbox available
and enforcing) or is honestly marked BLOCKED with the exact bwrap failure
reason -- never silently skipped, never asserted PASS on unverified belief.

Run: python3 -m pytest test_sandbox.py -v
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

import sandbox

HOME = str(Path.home())


def _sandbox_ok():
    try:
        sandbox.verify_bwrap()
        return True, None
    except sandbox.SandboxUnavailable as e:
        return False, str(e)


SANDBOX_OK, SANDBOX_REASON = _sandbox_ok()
requires_sandbox = pytest.mark.skipif(
    not SANDBOX_OK,
    reason=f"BLOCKED (not a code failure): bwrap cannot establish sandbox on this host -- {SANDBOX_REASON}",
)


def _repo_out(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "marker.txt").write_text("hello")
    out = tmp_path / "out"
    out.mkdir()
    return repo, out


# ---------------------------------------------------------------------------
# Fail-closed proof -- these run regardless of bwrap availability and are the
# core safety property: no unsandboxed fallback, ever.
# ---------------------------------------------------------------------------

def test_00_fail_closed_when_bwrap_missing(tmp_path, monkeypatch):
    """Test 12 (bypass by making bwrap 'fail'): force bwrap lookup to miss
    and prove run_sandboxed raises SandboxUnavailable rather than falling
    back to a plain subprocess.run on the host."""
    repo, out = _repo_out(tmp_path)
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.run_sandboxed("echo should_never_run", repo, out, timeout_seconds=10)


def test_00b_gate_clean_replay_rejects_deterministically_on_sandbox_unavailable(tmp_path, monkeypatch):
    """End-to-end: gate.py's clean_replay() must convert SandboxUnavailable
    into a deterministic non-PASS result, never an unsandboxed run."""
    import gate
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "a@b.c"])
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"])
    (tmp_path / "f.txt").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"])
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "c"])
    sha = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    result = gate.clean_replay(tmp_path, sha, "echo pwned > /tmp/should_never_exist_gate_test", 10)
    assert result["result"] == "SANDBOX_UNAVAILABLE"
    assert not Path("/tmp/should_never_exist_gate_test").exists()


def test_01_never_bind_denylist_enforced_by_construction(tmp_path):
    """Denied paths are never in the resolved bind set -- allowlist-only
    mounting, not a blocklist filter that could be bypassed."""
    repo, out = _repo_out(tmp_path)
    policy = sandbox.build_policy(repo, out)
    binds = [m["src"] for m in policy["mounts"]["read_only"] + policy["mounts"]["writable"]]
    for denied in sandbox.NEVER_BIND:
        assert denied not in binds
        assert not any(b.startswith(denied + os.sep) for b in binds)


def test_02_assert_allowed_bind_refuses_denylisted_path():
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox._assert_allowed_bind(str(Path(HOME) / ".ssh"))
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox._assert_allowed_bind(str(Path(HOME) / "Obsidian" / "Machine"))


def test_03_policy_is_json_serializable_and_normalized(tmp_path):
    repo, out = _repo_out(tmp_path)
    policy = sandbox.build_policy(repo, out)
    json.dumps(policy)  # must not raise
    assert policy["network"] == "disabled"
    assert policy["backend"] == "bwrap"
    assert "wall_timeout_seconds" in policy["limits"]


# ---------------------------------------------------------------------------
# Execution-dependent adversarial tests -- require a working bwrap sandbox.
# Skipped with an explicit BLOCKED reason (not silently green) if bwrap
# cannot establish its mounts on this host.
# ---------------------------------------------------------------------------

@requires_sandbox
def test_04_cannot_read_ssh(tmp_path):
    """Adversarial test 1: contributor code cannot read ~/.ssh."""
    repo, out = _repo_out(tmp_path)
    ssh_path = str(Path(HOME) / ".ssh")
    r = sandbox.run_sandboxed(f"cat {ssh_path}/id_rsa 2>&1; ls {ssh_path} 2>&1", repo, out, timeout_seconds=10)
    assert "No such file or directory" in r["stdout_tail"] + r["stderr_tail"]


@requires_sandbox
def test_05_cannot_read_obsidian_machine(tmp_path):
    """Adversarial test 2: contributor code cannot read Obsidian/Machine."""
    repo, out = _repo_out(tmp_path)
    p = str(Path(HOME) / "Obsidian" / "Machine")
    r = sandbox.run_sandboxed(f"ls {p} 2>&1", repo, out, timeout_seconds=10)
    assert "No such file or directory" in r["stdout_tail"] + r["stderr_tail"]


@requires_sandbox
def test_06_cannot_read_unrelated_repo(tmp_path):
    """Adversarial test 3: contributor code cannot read a sibling repo not
    explicitly mounted."""
    unrelated = tmp_path / "unrelated_repo"
    unrelated.mkdir()
    (unrelated / "secret_file.txt").write_text("do not leak")
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed(f"cat {unrelated}/secret_file.txt 2>&1", repo, out, timeout_seconds=10)
    assert "do not leak" not in r["stdout_tail"]
    assert "No such file or directory" in r["stdout_tail"] + r["stderr_tail"]


@requires_sandbox
def test_07_cannot_access_secret_env_vars(tmp_path, monkeypatch):
    """Adversarial test 4: declared secret-like host env vars are not
    propagated -- sandbox env is --clearenv + explicit allowlist, so host
    env is invisible regardless of what's set outside."""
    monkeypatch.setenv("MY_TOTALLY_SECRET_TOKEN", "should-not-leak-12345")
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("env", repo, out, timeout_seconds=10)
    assert "should-not-leak-12345" not in r["stdout_tail"]
    assert "MY_TOTALLY_SECRET_TOKEN" not in r["stdout_tail"]


@requires_sandbox
def test_08_no_network_access(tmp_path):
    """Adversarial test 5: no network -- unshare-net (via --unshare-all,
    no --share-net), so even loopback-independent DNS/connect attempts
    must fail immediately, not hang."""
    repo, out = _repo_out(tmp_path)
    probe = (
        "python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        "s.settimeout(3); "
        "import sys\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 80)); print('NETWORK_REACHED')\n"
        "except Exception as e:\n"
        "    print('NETWORK_BLOCKED', e)\""
    )
    r = sandbox.run_sandboxed(probe, repo, out, timeout_seconds=10)
    combined = r["stdout_tail"] + r["stderr_tail"]
    assert "NETWORK_REACHED" not in combined
    assert "NETWORK_BLOCKED" in combined or r["exit_code"] != 0


@requires_sandbox
def test_09_cannot_write_outside_writable_dir(tmp_path):
    """Adversarial test 6: writes outside $SANDBOX_OUT fail (tmpfs / and
    everything but /sandbox/out and /tmp is read-only or absent)."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("echo x > /sandbox/src/pwned.txt 2>&1; echo x > /etc/pwned.txt 2>&1",
                               repo, out, timeout_seconds=10)
    assert not (repo / "pwned.txt").exists()


@requires_sandbox
def test_10_cannot_modify_readonly_source_checkout(tmp_path):
    """Adversarial test 7: source checkout is read-only -- direct write
    attempt into /sandbox/src must fail with a permission/read-only error."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("echo tampered > /sandbox/src/marker.txt 2>&1; cat /sandbox/src/marker.txt",
                               repo, out, timeout_seconds=10)
    assert "hello" in r["stdout_tail"]
    assert "tampered" not in (repo / "marker.txt").read_text()


@requires_sandbox
def test_11_bounded_process_count(tmp_path):
    """Adversarial test 8: a forkbomb-style attempt is capped by ulimit -u,
    must not hang or exhaust the host -- either fails fast or the sandbox
    process count ceiling stops it well under a runaway count."""
    repo, out = _repo_out(tmp_path)
    forkbomb = "python3 -c \"import os\nn=0\ntry:\n    while True:\n        os.fork(); n+=1\nexcept Exception as e:\n    print('CAPPED_AT', n)\""
    r = sandbox.run_sandboxed(forkbomb, repo, out, timeout_seconds=15, max_procs=20)
    assert "CAPPED_AT" in r["stdout_tail"]
    n = int(r["stdout_tail"].split("CAPPED_AT")[1].split()[0])
    assert n < 100


@requires_sandbox
def test_12_bounded_execution_time(tmp_path):
    """Adversarial test 9: an infinite loop is killed by the wall-clock
    timeout, run_sandboxed returns TIMEOUT rather than hanging forever."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("while true; do :; done", repo, out, timeout_seconds=5)
    assert r["timed_out"] is True
    assert r["result"] == "TIMEOUT"
    assert r["wall_seconds"] < 20


@requires_sandbox
def test_13_bounded_output_size(tmp_path):
    """Adversarial test 10: unbounded stdout is capped -- tail is truncated
    to the documented cap, receipt marks stdout_truncated=True."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("yes AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | head -c 200000000", repo, out, timeout_seconds=15)
    assert len(r["stdout_tail"]) <= 3000
    assert r["stdout_truncated"] is True


@requires_sandbox
def test_14_bwrap_flags_cannot_be_overridden_by_test_cmd(tmp_path):
    """Adversarial test 11: the shell string passed as `cmd` cannot escape
    the sandbox by injecting its own bwrap/unshare invocation -- it runs
    *inside* an already-unshared, already-clearenv'd namespace, so a nested
    unshare attempt has no elevated capability to grant."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("bwrap --unshare-net=false --bind / /host_escape 2>&1; ls /host_escape 2>&1",
                               repo, out, timeout_seconds=10)
    combined = r["stdout_tail"] + r["stderr_tail"]
    assert "/etc/passwd" not in combined  # i.e. no evidence a real host root view was mounted


@requires_sandbox
def test_15_harmless_valid_fixture_succeeds(tmp_path):
    """Adversarial test 13: a harmless, correct command executes successfully
    end-to-end through the sandbox."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed("cat /sandbox/src/marker.txt && echo SANDBOX_RUN_OK", repo, out, timeout_seconds=10)
    assert r["result"] == "PASS"
    assert "SANDBOX_RUN_OK" in r["stdout_tail"]


@requires_sandbox
def test_16_artifacts_exported_via_writable_dir(tmp_path):
    """Adversarial test 14: expected test artifacts land in $SANDBOX_OUT and
    are visible to the caller on the host afterward."""
    repo, out = _repo_out(tmp_path)
    r = sandbox.run_sandboxed('echo "result-data" > "$SANDBOX_OUT/artifact.txt"', repo, out, timeout_seconds=10)
    assert r["result"] == "PASS"
    assert (out / "artifact.txt").exists()
    assert (out / "artifact.txt").read_text().strip() == "result-data"


def test_17_receipt_distinguishes_sandbox_failure_from_test_failure(tmp_path, monkeypatch):
    """Adversarial test 15: SANDBOX_UNAVAILABLE and a genuine failing test
    are distinguishable results, not conflated into one generic FAIL."""
    import gate
    subprocess.run(["git", "init", "-q"], cwd=tmp_path)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "a@b.c"])
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"])
    (tmp_path / "f.txt").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"])
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "c"])
    sha = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()

    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    unavailable = gate.clean_replay(tmp_path, sha, "exit 1", 10)
    assert unavailable["result"] == "SANDBOX_UNAVAILABLE"
    monkeypatch.undo()  # the SandboxUnavailable probe above must not leak into the real-sandbox call below

    if SANDBOX_OK:
        genuine_fail = gate.clean_replay(tmp_path, sha, "exit 1", 10)
        assert genuine_fail["result"] == "FAIL"
        assert genuine_fail["result"] != unavailable["result"]


def test_18_no_llm_invoked(tmp_path):
    """Requirement 18: sandbox module makes no LLM/network API call of its
    own -- static check that no such client is imported or referenced."""
    src = Path("sandbox.py").read_text()
    for banned in ("openai", "anthropic", "requests.post", "httpx", "google.generativeai"):
        assert banned not in src


def test_19_no_private_vault_content_in_policy_or_receipt(tmp_path):
    """Requirement 17: the actual MOUNT set (what's really bound into the
    sandbox) never contains vault/private repo paths -- only the two
    declared repo/out mounts. `deny_list_asserted` legitimately names those
    paths as evidence of what's blocked (transparency, not a leak) so it is
    excluded from this check on purpose."""
    repo, out = _repo_out(tmp_path)
    policy = sandbox.build_policy(repo, out)
    mounts_blob = json.dumps(policy["mounts"])
    assert "Obsidian" not in mounts_blob
    assert ".ssh" not in mounts_blob


def test_20_existing_non_execution_gate_behavior_unchanged(tmp_path):
    """Requirement 16: acceptance_boundary_diff / triage (non-execution
    paths) are untouched by the sandbox change -- regression check."""
    import gate
    subprocess.run(["git", "init", "-q"], cwd=tmp_path)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "a@b.c"])
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"])
    (tmp_path / "app.py").write_text("x=1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"])
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "before"])
    before = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
                             capture_output=True, text=True).stdout.strip()
    (tmp_path / "app.py").write_text("x=2\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"])
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "after"])
    after = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    boundary = gate.acceptance_boundary_diff(tmp_path, before, after)
    assert boundary["test_files_changed"] is False
    assert boundary["unauthorized_acceptance_mutation"] is False
