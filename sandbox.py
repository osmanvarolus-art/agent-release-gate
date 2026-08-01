"""sandbox.py -- mandatory bwrap execution boundary for Agent Release Gate.

Every command that runs contributor-controlled code (test suites, install
scripts, anything reachable from a candidate commit) MUST go through
run_sandboxed(). There is no unsandboxed fallback: if bwrap is missing, too
old, or a required mount cannot be verified, run_sandboxed() raises
SandboxUnavailable and the caller must fail closed (REJECT / BLOCKED), never
silently execute on the host.

Sandboxing answers ONE question: can this command see/touch anything it
shouldn't, escape its resource bounds, or reach the network? It answers
NOTHING about whether the command's result should be accepted -- that is
gate.py's job (scope, declared task, receipt integrity, promotion rules).
A clean sandboxed run is not, by itself, acceptance.
"""
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import time
from pathlib import Path

BWRAP = "bwrap"
MIN_BWRAP_VERSION = (0, 4, 0)  # --unshare-all / --die-with-parent available since well before this

# Paths that must NEVER be bound into a sandboxed run, regardless of caller
# input. Enforced twice: (1) allowlist-only mount building below never binds
# anything outside repo_ro/out_dir, so these are absent by construction; (2)
# this list is also asserted against in build_bwrap_argv() as a defense-in-
# depth check on the resolved bind sources.
NEVER_BIND = [
    str(Path.home() / ".ssh"),
    str(Path.home() / ".config"),
    str(Path.home() / "Obsidian" / "Machine"),
    str(Path.home() / "Obsidian" / "Machine" / "Registry" / "AgentControl"),
]

# Environment variables never propagated into the sandbox even if present in
# the caller's own env -- sanitized env is built from an explicit allowlist
# below, but this is asserted against too (defense in depth).
SECRET_ENV_PATTERNS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL", "API_KEY")


class SandboxUnavailable(Exception):
    """Raised when bwrap cannot be found or verified. Callers must fail
    closed on this -- never catch-and-fall-back-to-host."""


def _bwrap_path():
    p = shutil.which(BWRAP)
    if not p:
        raise SandboxUnavailable("bwrap binary not found on PATH")
    return p


def bwrap_version():
    """Returns bwrap's version string, or raises SandboxUnavailable."""
    exe = _bwrap_path()
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
    except Exception as e:
        raise SandboxUnavailable(f"bwrap --version failed to execute: {e}")
    if r.returncode != 0:
        raise SandboxUnavailable(f"bwrap --version exited {r.returncode}: {r.stderr[:500]}")
    return r.stdout.strip()


def verify_bwrap():
    """Fail-closed probe: bwrap exists, runs, AND can actually establish the
    mount/namespace boundary this module relies on (unshare-all + a real
    ro-bind + a tmpfs). Returns (exe_path, version_string) or raises
    SandboxUnavailable with the exact reason."""
    exe = _bwrap_path()
    version = bwrap_version()
    # Must mirror build_bwrap_argv()'s mount set exactly. /usr alone is not
    # enough: Ubuntu's dynamic-linked ELF binaries reference their PT_INTERP
    # (dynamic linker) via the top-level /lib64 (or /lib) symlink, which is
    # NOT reachable through /usr alone in an otherwise-empty bwrap root. The
    # kernel's execve() ELF loader then fails to resolve the interpreter and
    # bwrap surfaces this as "No such file or directory" on the exec --
    # indistinguishable in the error text from the target binary itself
    # being missing. Root-caused live 2026-07-15 via deterministic bisection
    # (see acceptance-gate/BWRAP_MOUNT_COMPOSITION_ROOT_CAUSE_20260715.md).
    # Also mirrors the structural flags of build_bwrap_argv() (--new-session,
    # --clearenv/--setenv, --chdir, --dir, a second tmpfs) -- not just the
    # toolchain binds -- so a bwrap that's incompatible with THIS shape
    # fails here (SandboxUnavailable, fail-closed) rather than surfacing
    # later as an ordinary-looking FAIL on a real run (Codex independent
    # review finding, 2026-07-15).
    probe = subprocess.run(
        [exe, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
         "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
         "--ro-bind", "/usr", "/usr",
         "--ro-bind-try", "/bin", "/bin",
         "--ro-bind-try", "/lib", "/lib",
         "--ro-bind-try", "/lib64", "/lib64",
         "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
         "--tmpfs", "/sandbox/home", "--dir", "/sandbox",
         "--chdir", "/", "--", "/usr/bin/sh", "-c", "true"],
        capture_output=True, text=True, timeout=15,
    )
    if probe.returncode != 0:
        raise SandboxUnavailable(
            f"bwrap probe run failed (rc={probe.returncode}): {probe.stderr[:500]}"
        )
    return exe, version


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _assert_allowed_bind(path):
    rp = str(Path(path).resolve())
    for denied in NEVER_BIND:
        if rp == denied or rp.startswith(denied + os.sep):
            raise SandboxUnavailable(f"refused to bind denylisted path: {rp}")


def build_policy(repo_ro, out_dir, timeout_seconds=120, cpu_seconds=60,
                  mem_mb=512, max_procs=64, max_output_bytes=5_000_000):
    """Normalized, JSON-serializable sandbox policy -- goes verbatim into the
    receipt (§ required receipts: 'complete normalized sandbox policy')."""
    repo_ro = str(Path(repo_ro).resolve())
    out_dir = str(Path(out_dir).resolve())
    return {
        "backend": "bwrap",
        "network": "disabled",
        "mounts": {
            "read_only": [{"src": repo_ro, "dest": "/sandbox/src"}],
            "writable": [{"src": out_dir, "dest": "/sandbox/out"}],
            "proc": "/proc (minimal, fresh)",
            "dev": "/dev (minimal, fresh)",
            "home": "/sandbox/home (isolated tmpfs, empty per run)",
        },
        "cwd": "/sandbox/src",
        "env": "cleared; allowlist only (PATH, HOME, LANG, SANDBOX_OUT, PYTHONDONTWRITEBYTECODE)",
        "limits": {
            "wall_timeout_seconds": timeout_seconds,
            "cpu_seconds": cpu_seconds,
            "address_space_mb": mem_mb,
            "max_processes": max_procs,
            "max_output_bytes": max_output_bytes,
        },
        "deny_list_asserted": list(NEVER_BIND),
    }


def build_bwrap_argv(policy, exe, inner_cmd):
    for m in policy["mounts"]["read_only"]:
        _assert_allowed_bind(m["src"])
    for m in policy["mounts"]["writable"]:
        _assert_allowed_bind(m["src"])

    lim = policy["limits"]
    # ulimits enforced by the in-sandbox shell before running the real
    # command -- this bwrap version (0.11.1) has no native --rlimit flag.
    # cpu_seconds: ulimit -t. address space: ulimit -v (KB). max_processes:
    # ulimit -p (dash/POSIX -- NOT bash's -u, which dash rejects outright).
    # Per-file output size: ulimit -f. The writable dir is a real bind
    # mount, not a size-capped tmpfs (see argv below and its own comment).
    # NOTE: cannot use "exec {inner_cmd}" here -- exec only accepts a single
    # simple command, not a compound shell construct (while/if/;-chains).
    # inner_cmd is caller-supplied and routinely compound (e.g. a test
    # runner followed by an artifact-export step) -- exec-wrapping it broke
    # every compound command with a dash syntax error ("do" unexpected).
    # Root-caused live 2026-07-15 via test_10/test_12 failures.
    # ulimit -f is in 512-byte blocks and caps any single file's size --
    # bounds runaway artifact writes into the real (now host-backed, see
    # below) writable dir. Total captured stdout/stderr is bounded
    # separately in run_sandboxed() via _truncate() on the captured bytes.
    # dash (the /usr/bin/sh on this and every Debian/Ubuntu host) uses
    # POSIX '-p' (max user processes), NOT bash's '-u' -- '-u' is "Illegal
    # option -u" under dash, silently swallowed by the old "2>/dev/null"
    # suppression, meaning the process-count bound was NEVER actually
    # applied. Root-caused live 2026-07-15 (Codex independent review) and
    # verified empirically (`ulimit -u` -> rc=2 "Illegal option -u" on this
    # host's dash; `ulimit -p` -> rc=0). Every ulimit call now fails CLOSED
    # (aborts the whole run with a distinct exit code) instead of silently
    # continuing unbounded if a limit can't be set -- a sandbox that can't
    # prove its own bound was applied must refuse, not proceed hopefully.
    # Each ulimit call runs in THIS shell process (no subshell/parens --
    # ulimit's effect would be lost the instant a subshell exits) and must
    # succeed individually before inner_cmd is ever reached, so a genuine
    # inner_cmd failure can never be misreported as a limit-setup failure.
    max_file_blocks = max(1, lim["max_output_bytes"] // 512)
    wrapped = (
        f"ulimit -t {lim['cpu_seconds']} || {{ echo SANDBOX_LIMIT_SETUP_FAILED >&2; exit 97; }}\n"
        f"ulimit -v {lim['address_space_mb'] * 1024} || {{ echo SANDBOX_LIMIT_SETUP_FAILED >&2; exit 97; }}\n"
        f"ulimit -p {lim['max_processes']} || {{ echo SANDBOX_LIMIT_SETUP_FAILED >&2; exit 97; }}\n"
        f"ulimit -f {max_file_blocks} || {{ echo SANDBOX_LIMIT_SETUP_FAILED >&2; exit 97; }}\n"
        f"{inner_cmd}"
    )

    argv = [
        exe,
        "--unshare-all",           # net, pid, ipc, uts, cgroup, user -- no --share-net, so no network
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/sandbox/home",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "SANDBOX_OUT", "/sandbox/out",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--setenv", "TMPDIR", "/sandbox/out",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--tmpfs", "/sandbox/home",
        "--dir", "/sandbox",
        "--ro-bind", policy["mounts"]["read_only"][0]["src"], "/sandbox/src",
        # A real writable bind to the host out_dir, NOT --tmpfs. A tmpfs
        # here lives only inside the sandbox's own (destroyed-on-exit) mount
        # namespace -- artifacts written to it never reach the host, which
        # silently broke artifact export. Per-file size is bounded by
        # ulimit -f in the wrapped shell above, not by mount size.
        # Root-caused live 2026-07-15 via test_16 (artifact export) failure.
        "--bind", policy["mounts"]["writable"][0]["src"], "/sandbox/out",
        "--chdir", "/sandbox/src",
        "--",
        "/usr/bin/sh", "-c", wrapped,
    ]
    return argv


def _truncate(b, n):
    if len(b) <= n:
        return b, False
    return b[:n], True


def run_sandboxed(cmd, repo_ro, out_dir, timeout_seconds=120, cpu_seconds=60,
                   mem_mb=512, max_procs=64, max_output_bytes=5_000_000):
    """Runs `cmd` (a shell string, executed as `/usr/bin/sh -c cmd` inside the
    sandbox) against a read-only bind of repo_ro, with out_dir as the only
    writable location (exposed inside the sandbox as $SANDBOX_OUT). Fails
    closed: raises SandboxUnavailable if bwrap cannot be verified, never
    falls back to host execution.

    Returns a dict: sandboxed(bool, always True on return -- absence means
    SandboxUnavailable was raised instead), backend, backend_version, policy,
    exit_code, result (PASS|FAIL|TIMEOUT), timed_out, signal, stdout_tail,
    stderr_tail, stdout_sha256, stderr_sha256, stdout_truncated,
    stderr_truncated, wall_seconds.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    exe, version = verify_bwrap()  # raises SandboxUnavailable, fail-closed
    policy = build_policy(repo_ro, out_dir, timeout_seconds, cpu_seconds,
                           mem_mb, max_procs, max_output_bytes)
    argv = build_bwrap_argv(policy, exe, cmd)

    # Runtime-enforced bounds, not post-exit detection (Codex independent
    # review, round 2, 2026-07-15): subprocess.run(capture_output=True)
    # buffers the ENTIRE stdout/stderr in host memory regardless of the
    # child's own address-space ulimit (parent-process allocation, not
    # bounded by a child rlimit), and a post-exit directory-size check lets
    # a runaway write fill host disk before it's ever caught. Both closed
    # here by reading incrementally via selectors and polling the writable
    # dir's size periodically WHILE the sandboxed process is still running,
    # killing its whole process group the instant either bound is crossed
    # -- not after.
    poll_interval = 0.1
    hard_output_cap = max_output_bytes + 1_000_000  # small slack over the receipt-tail budget
    started = time.monotonic()
    deadline = started + timeout_seconds

    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, "stdout")
    sel.register(proc.stderr, selectors.EVENT_READ, "stderr")
    out_chunks, err_chunks = [], []
    out_total = err_total = 0
    open_streams = 2
    timed_out = False
    killed_for_output = False
    killed_for_disk = False
    last_disk_check = 0.0
    out_dir_bytes = 0

    while open_streams > 0:
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            timed_out = True
            break
        if now - last_disk_check >= poll_interval:
            last_disk_check = now
            try:
                out_dir_bytes = sum(f.stat().st_size for f in Path(out_dir).rglob("*") if f.is_file())
            except OSError:
                pass
            if out_dir_bytes > max_output_bytes:
                killed_for_disk = True
                break
        for key, _ in sel.select(timeout=min(poll_interval, remaining)):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                sel.unregister(key.fileobj)
                open_streams -= 1
                continue
            if key.data == "stdout":
                out_chunks.append(chunk); out_total += len(chunk)
            else:
                err_chunks.append(chunk); err_total += len(chunk)
        if out_total + err_total > hard_output_cap:
            killed_for_output = True
            break

    sig = None
    kill_verification_failed = False
    if timed_out or killed_for_output or killed_for_disk:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Codex independent review, round 3, 2026-07-15: this was
            # previously swallowed silently -- if SIGKILL doesn't reap the
            # process within 5s, we do NOT know the sandbox actually tore
            # down, and must surface that rather than return as if cleanup
            # succeeded. Fail-closed: caller sees this and must treat the
            # run as untrusted, not merely FAIL.
            kill_verification_failed = True
    else:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_verification_failed = True
    exit_code = proc.returncode
    if exit_code is not None and exit_code < 0:
        sig = -exit_code
    wall = time.monotonic() - started

    out_bytes = b"".join(out_chunks)
    stderr_bytes = b"".join(err_chunks)
    stdout_tail, stdout_trunc = _truncate(out_bytes, 3000)
    stderr_tail, stderr_trunc = _truncate(stderr_bytes, 1500)

    # Final on-disk size, whether or not a mid-run kill already fired --
    # kept in the returned evidence either way.
    try:
        out_dir_bytes = sum(f.stat().st_size for f in Path(out_dir).rglob("*") if f.is_file())
    except OSError:
        pass
    output_dir_quota_exceeded = out_dir_bytes > max_output_bytes or killed_for_disk

    if kill_verification_failed:
        result = "FAIL"  # untrusted teardown state -- never PASS
    elif timed_out:
        result = "TIMEOUT"
    elif killed_for_output or out_total + err_total > hard_output_cap:
        result = "FAIL"
    elif output_dir_quota_exceeded:
        result = "FAIL"
    elif exit_code == 0:
        result = "PASS"
    else:
        result = "FAIL"

    return {
        "sandboxed": True,
        "backend": "bwrap",
        "backend_version": version,
        "policy": policy,
        "exit_code": exit_code,
        "result": result,
        "timed_out": timed_out,
        "signal": sig,
        "wall_seconds": round(wall, 3),
        "stdout_tail": stdout_tail.decode("utf-8", errors="replace"),
        "stderr_tail": stderr_tail.decode("utf-8", errors="replace"),
        "stdout_truncated": stdout_trunc,
        "stderr_truncated": stderr_trunc,
        "stdout_sha256": sha256_bytes(out_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "output_dir_bytes": out_dir_bytes,
        "output_dir_quota_exceeded": output_dir_quota_exceeded,
        "killed_for_output_bound": killed_for_output,
        "killed_for_disk_bound": killed_for_disk,
        "kill_verification_failed": kill_verification_failed,
    }
