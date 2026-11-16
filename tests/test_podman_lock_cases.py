#!/usr/bin/env python3
"""Suite nonroot: the pair-wide lock is held by a kernel lock, and the cases read it.

``MN-LOCK``/``MN-LOCK-LOSS``/``MN-LOCK-PATH`` run against the two containers of a
live two-node contour, so a unit test cannot own that contour. What it can own is
everything the live run relies on being right, and this suite does it without
faking the mechanism:

* The lock holder program (``preflight.LOCK_HOLDER_SCRIPT``) is executed for real
  against a temporary directory, so each refusal sentence is asserted against the
  program that produces it, together with the object still being the object it
  was.
* ``RemotePairLock`` is the product's own class. Only the transport is replaced:
  its "SSH session into the container" becomes a local process, and the two
  containers' filesystems become two temporary directories. The flock is a real
  ``flock``, the lease is the file the holder published, a lost session is a
  ``SIGTERM`` to the holder's own pid, and the lease validator is the product's
  own ``modules/lock.sh``.
* The three case drivers are then run whole, and each guard is damaged on its own
  so the assertion that protects it is seen to fail for that reason and no other.

What is not covered here is the container itself: ``_pair`` — the SSH bootstrap
into Master and Worker — is replaced, and the cases' own absolute paths are
translated on the way to the temporary directory and back. That contour is proven
by the live Podman run, not by this suite.

``MN-LOCK-CLI``/``MN-LOCK-NESTED`` run the shipped commands inside a live host,
so they are not driven here either: doing that would execute the real
``gowave-auto.sh`` as an unprivileged process. What is held here is what the live
run relies on being right — the eight entry points and the marker each one prints
after it took the lock, the sentence behind the restore's archive check, and the
command the case hands ``podman exec`` (a lease read from a file by the child's
own shell, never spliced into ``argv``).
"""
import contextlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from tools.live_vps import deployment, preflight  # noqa: E402
from tools.live_vps.runstate import (  # noqa: E402
    MUTATING_PHASES,
    pair_lock_gate,
)
from tools.live_vps.ssh import SSHResult  # noqa: E402
from tools.podman_e2e import catalog, lock_cases  # noqa: E402

CASES = {
    lock_cases.LOCK_CASE_ID: lock_cases.case_pair_lock,
    lock_cases.LOCK_LOSS_CASE_ID: lock_cases.case_lock_loss,
    lock_cases.LOCK_PATH_CASE_ID: lock_cases.case_lock_path,
}

#: The two cases that run the shipped commands inside a live host. They are not
#: driven from this suite — doing so would execute the real ``gowave-auto.sh`` as
#: an unprivileged process and let it start package work before its refusal — but
#: their registration and the table they drive are readable here.
CLI_CASES = {
    lock_cases.CLI_CASE_ID: lock_cases.case_cli_entry_points,
    lock_cases.NESTED_CASE_ID: lock_cases.case_nested_lease,
}

ALL_CASES = {**CASES, **CLI_CASES}

MASTER_NAME = "master-1"
WORKER_NAME = "worker-1"
MASTER_ADDRESS = "10.89.0.2"
WORKER_ADDRESS = "10.89.0.3"


# --------------------------------------------------------------------- sandbox


class Sandbox:
    """One container's lock directory, as a temporary directory on this host.

    The cases name production paths (``/run/lock/...``, ``/repo/modules/lock.sh``)
    because that is what the product uses. A command is translated on its way to
    the filesystem and its output is translated back, so the case reads the
    sentence it would read on a host while the bytes live in ``tmp``.
    """

    def __init__(self, root: Path, name: str):
        self.name = name
        self.lock_dir = root / name / "run" / "lock"
        self.lock_dir.mkdir(parents=True)
        self.lock_file, self.lease_file = self.paths()

    def paths(self):
        """(lock file, lease file) as this sandbox spells them."""
        return (
            self.lock_dir / lock_cases.LOCK_NAME,
            self.lock_dir / Path(lock_cases.LEASE_PATH).name,
        )

    def translate(self, text: str) -> str:
        return (
            text.replace(lock_cases.LOCK_DIR, str(self.lock_dir))
            .replace("/repo/modules", str(REPO_ROOT / "modules"))
        )

    def untranslate(self, text: str) -> str:
        return text.replace(str(self.lock_dir), lock_cases.LOCK_DIR)

    def lease(self):
        """The lease record this sandbox holds, or {} when there is not one."""
        try:
            return json.loads(self.lease_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}


def _object_record(path):
    """What ``lstat`` says about a path, through the case's own object script."""
    completed = subprocess.run(
        [sys.executable, "-c", lock_cases._OBJECT_SCRIPT, str(path)],
        capture_output=True, text=True, timeout=60,
    )
    return json.loads(completed.stdout)


def _lock_is_free(path) -> bool:
    completed = subprocess.run(
        ["bash", "-c", f"exec 9>>{path} && if flock -n 9; then echo FREE; else echo HELD; fi"],
        capture_output=True, text=True, timeout=60,
    )
    return completed.stdout.strip() == "FREE"


class LocalSSH:
    """The one thing ``RemotePairLock`` uses an SSH client for, run locally."""

    def __init__(self, address: str, sandbox: Sandbox):
        self.host = address
        self.sandbox = sandbox
        self.closed = False

    def _build_ssh_cmd(self, remote_cmd: str):
        words = shlex.split(remote_cmd)
        if words[:2] != ["python3", "-c"]:
            raise AssertionError(
                f"the lock holder is not started as 'python3 -c <script>': {words[:2]!r}"
            )
        return [sys.executable, "-c", _relocate(words[2], self.sandbox)]

    def close(self):
        self.closed = True


class LocalPodman:
    """``podman exec`` over the sandboxes, so the cases' commands really run."""

    def __init__(self, sandboxes):
        self.sandboxes = sandboxes
        self.calls = []

    def exec(self, name, argv, check=True, input_text=None, timeout=None):
        sandbox = self.sandboxes[name]
        argv = list(argv)
        self.calls.append({"container": name, "argv": argv})
        if argv[0] == "kill":
            os.kill(int(argv[2]), signal.SIGTERM)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[0] == "cat":
            path = Path(sandbox.translate(argv[1]))
            if not path.exists():
                return types.SimpleNamespace(returncode=1, stdout="", stderr="missing")
            return types.SimpleNamespace(
                returncode=0, stdout=sandbox.untranslate(path.read_text(encoding="utf-8")),
                stderr="",
            )
        command = [argv[0]] + [sandbox.translate(argument) for argument in argv[1:]]
        if command[0] == "python3" and command[1] == "-c":
            command[0] = sys.executable
            # The script itself is translated already; only its path arguments are
            # filesystem-relative in a way the sandbox has to move.
            command = [command[0], "-c"] + [sandbox.translate(item) for item in argv[2:]]
        completed = subprocess.run(
            command, input=input_text, capture_output=True, text=True,
            timeout=timeout or 120,
        )
        if check and completed.returncode != 0:
            raise AssertionError(
                f"podman exec {name} {argv[:2]} failed ({completed.returncode}): "
                f"{completed.stderr.strip()}"
            )
        return types.SimpleNamespace(
            returncode=completed.returncode,
            stdout=sandbox.untranslate(completed.stdout),
            stderr=sandbox.untranslate(completed.stderr),
        )


class StubbornSSH(LocalSSH):
    """A session whose remote holder cannot be reached by a signal to the client.

    ``ssh`` starts the holder on the other side of a channel, so terminating or
    killing the client reaches nothing on that side. The holder here is the
    shim's detached child for the same reason, which leaves the session — EOF on
    the pipe — as the only way to free the lock.
    """

    SHIM = (
        "import subprocess, sys\n"
        "child = subprocess.Popen(sys.argv[1:], stdin=0, start_new_session=True)\n"
        "raise SystemExit(child.wait())\n"
    )

    def _build_ssh_cmd(self, remote_cmd: str):
        return [sys.executable, "-c", self.SHIM, *super()._build_ssh_cmd(remote_cmd)]


def _relocate(script: str, sandbox: Sandbox) -> str:
    """Point a holder program at ``sandbox`` while it keeps speaking production paths.

    Only the two filesystem uses of the lock directory move; every sentence the
    program can say keeps naming ``/run/lock``, because that is the sentence the
    case asserts and the sentence an operator would read on the host.
    """
    directory = repr(str(sandbox.lock_dir))
    for anchor, replacement in (
        ("os.makedirs(LOCK_DIR, exist_ok=True)", f"os.makedirs({directory}, exist_ok=True)"),
        (
            "os.open(LOCK_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)",
            f"os.open({directory}, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)",
        ),
    ):
        count = script.count(anchor)
        if count != 1:
            raise AssertionError(f"the holder anchor {anchor!r} occurs {count} times")
        script = script.replace(anchor, replacement)
    return script


def _holder_script(sandbox: Sandbox, run_id="run-1", host=MASTER_ADDRESS) -> str:
    return _relocate(preflight.LOCK_HOLDER_SCRIPT % (run_id, host), sandbox)


class HolderCase:
    """A temporary directory and the holders it started, cleaned up after."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-lock-holder-")
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.sandbox = Sandbox(self.root, MASTER_NAME)
        self.lock_file, self.lease_file = self.sandbox.paths()
        self._holders = []
        self.addCleanup(self._stop_holders)

    def _stop_holders(self):
        for process in self._holders:
            if process.poll() is None and process.stdin is not None:
                # The holder ends when its session does, so the sweep closes the
                # session before it resorts to a signal.
                with contextlib.suppress(OSError, ValueError):
                    process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        # A holder started by the product itself (``RemotePairLock``) is not in the
        # list above, and a case that was damaged mid-flight never reached the
        # release that would have ended it. The sandbox path is in every holder's
        # command line, so the sweep is exact rather than a wildcard kill.
        for sandbox in getattr(self, "sandboxes", {}).values():
            listing = subprocess.run(
                ["pgrep", "-f", str(sandbox.lock_dir)], capture_output=True, text=True,
            )
            for pid in listing.stdout.split():
                with contextlib.suppress(OSError):
                    os.kill(int(pid), signal.SIGKILL)

    def start_holder(self, sandbox=None, run_id="run-1", host=MASTER_ADDRESS):
        sandbox = sandbox or self.sandbox
        # stdin stays open for as long as the session would: the holder releases
        # its flock on EOF, so a DEVNULL here would end it before the case read it.
        process = subprocess.Popen(
            [sys.executable, "-c", _holder_script(sandbox, run_id, host)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self._holders.append(process)
        return process

    def published_token(self, process) -> str:
        line = process.stdout.readline().strip()
        if not line.startswith("LEASE_TOKEN:"):
            stderr = process.stderr.read().strip()
            raise AssertionError(f"the holder published no lease: {line!r} {stderr!r}")
        return line.split(":", 1)[1]

    def refusal(self, sandbox=None, run_id="run-1", host=MASTER_ADDRESS) -> str:
        sandbox = sandbox or self.sandbox
        process = self.start_holder(sandbox, run_id, host)
        process.wait(timeout=60)
        stderr = process.stderr.read()
        for line in stderr.splitlines():
            if line.startswith("LOCK_REFUSED:"):
                return line.split(":", 1)[1].strip()
        raise AssertionError(
            f"the holder exited {process.returncode} without refusing: {stderr.strip()!r}"
        )


class TestLockHolderProgram(HolderCase, unittest.TestCase):
    """Each refusal sentence, against the program that produces it."""

    def test_a_free_path_publishes_the_lease_it_holds(self):
        process = self.start_holder(run_id="run-holder", host=MASTER_ADDRESS)
        token = self.published_token(process)
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        record = self.sandbox.lease()
        self.assertEqual(record.get("run_id"), "run-holder")
        self.assertEqual(record.get("host"), MASTER_ADDRESS)
        self.assertEqual(record.get("holder_pid"), process.pid)
        self.assertEqual(record.get("lease_token"), token)
        self.assertEqual(
            self.lease_file.stat().st_mode & 0o777, 0o600,
            "the lease file is readable beyond the runner",
        )
        self.assertFalse(_lock_is_free(self.lock_file), "a published holder does not hold the lock")
        process.terminate()
        process.wait(timeout=60)
        self.assertTrue(_lock_is_free(self.lock_file), "the kernel lock outlived its holder")

    def test_a_holder_ends_when_the_session_that_started_it_does(self):
        # The kernel releases the flock when the holder dies, and a local `kill`
        # cannot reach a process on the other side of an SSH channel. The holder
        # therefore watches its own stdin, and closing it is the session ending.
        process = self.start_holder(run_id="run-session")
        self.published_token(process)
        self.assertFalse(_lock_is_free(self.lock_file), "the holder did not take the lock")
        process.stdin.close()
        self.assertEqual(process.wait(timeout=60), 0, "the holder did not end on EOF")
        self.assertTrue(_lock_is_free(self.lock_file), "the kernel lock outlived its session")

    def test_a_symlink_is_refused_and_left_a_symlink(self):
        os.symlink("/tmp/gowave-lock-target", self.lock_file)
        before = _object_record(self.lock_file)
        refusal = self.refusal()
        self.assertEqual(refusal, f"the lock file {lock_cases.LOCK_PATH} is a symlink")
        self.assertEqual(_object_record(self.lock_file), before)

    def test_a_directory_is_refused_as_a_directory(self):
        self.lock_file.mkdir()
        before = _object_record(self.lock_file)
        refusal = self.refusal()
        self.assertEqual(refusal, f"the lock file {lock_cases.LOCK_PATH} is a directory")
        self.assertEqual(_object_record(self.lock_file), before)

    def test_a_fifo_is_refused_as_not_a_regular_file(self):
        os.mkfifo(self.lock_file, mode=0o600)
        before = _object_record(self.lock_file)
        refusal = self.refusal()
        self.assertEqual(refusal, f"the lock file {lock_cases.LOCK_PATH} is not a regular file")
        self.assertEqual(_object_record(self.lock_file), before)

    def test_a_group_readable_file_is_refused_and_not_rewritten(self):
        self.lock_file.write_text("", encoding="utf-8")
        self.lock_file.chmod(0o644)
        before = _object_record(self.lock_file)
        refusal = self.refusal()
        self.assertEqual(
            refusal, f"the lock file {lock_cases.LOCK_PATH} grants group or other access"
        )
        self.assertEqual(_object_record(self.lock_file), before)

    @unittest.skipUnless(os.geteuid() == 0, "handing a file to another user needs CAP_CHOWN")
    def test_a_file_owned_by_another_user_is_refused(self):
        self.lock_file.write_text("", encoding="utf-8")
        self.lock_file.chmod(0o600)
        os.chown(self.lock_file, 65534, 65534)
        before = _object_record(self.lock_file)
        refusal = self.refusal()
        self.assertEqual(refusal, f"the lock file {lock_cases.LOCK_PATH} is not owned by the runner")
        self.assertEqual(_object_record(self.lock_file), before)

    def test_a_held_lock_is_refused_by_name(self):
        process = self.start_holder()
        self.published_token(process)
        refusal = self.refusal(run_id="run-2")
        self.assertEqual(refusal, lock_cases.HELD_SENTENCE)

    def test_a_symlinked_lock_directory_is_refused(self):
        moved = self.sandbox.lock_dir.with_name("lock.case")
        self.sandbox.lock_dir.rename(moved)
        os.symlink(moved, self.sandbox.lock_dir)
        try:
            refusal = self.refusal()
        finally:
            self.sandbox.lock_dir.unlink()
            moved.rename(self.sandbox.lock_dir)
        self.assertEqual(
            refusal,
            f"the lock directory {lock_cases.LOCK_DIR} is a symlink or not a directory",
        )


class TestPairLockOverLocalHolders(HolderCase, unittest.TestCase):
    """The product's ``RemotePairLock``, with only its transport replaced."""

    def setUp(self):
        super().setUp()
        self.sandboxes = {
            MASTER_NAME: self.sandbox,
            WORKER_NAME: Sandbox(self.root, WORKER_NAME),
        }
        self.clients = {
            MASTER_ADDRESS: LocalSSH(MASTER_ADDRESS, self.sandboxes[MASTER_NAME]),
            WORKER_ADDRESS: LocalSSH(WORKER_ADDRESS, self.sandboxes[WORKER_NAME]),
        }

    def pair(self, run_id="pair"):
        lock = preflight.RemotePairLock(
            self.clients[MASTER_ADDRESS], self.clients[WORKER_ADDRESS], run_id=run_id,
        )
        self.addCleanup(lock.release)
        return lock

    def test_the_pair_is_taken_in_address_order_and_publishes_two_leases(self):
        lock = self.pair()
        self.assertTrue(lock.acquire(), lock.last_error)
        self.assertEqual([client.host for client in lock.clients], [MASTER_ADDRESS, WORKER_ADDRESS])
        self.assertEqual(set(lock.lease_tokens), {MASTER_ADDRESS, WORKER_ADDRESS})
        self.assertEqual(len(set(lock.lease_tokens.values())), 2, "both hosts published one token")
        for address, sandbox in (
            (MASTER_ADDRESS, self.sandboxes[MASTER_NAME]),
            (WORKER_ADDRESS, self.sandboxes[WORKER_NAME]),
        ):
            record = sandbox.lease()
            self.assertEqual(record.get("run_id"), "pair")
            self.assertEqual(record.get("host"), address)
            self.assertEqual(record.get("lease_token"), lock.lease_tokens[address])
            self.assertFalse(_lock_is_free(sandbox.lock_file), f"{address} holds no kernel lock")

    def test_a_second_runner_is_refused_and_keeps_no_lease(self):
        owner = self.pair("owner")
        self.assertTrue(owner.acquire(), owner.last_error)
        intruder = self.pair("intruder")
        self.assertFalse(intruder.acquire())
        self.assertIn(lock_cases.HELD_SENTENCE, intruder.last_error)
        self.assertEqual(intruder.lease_tokens, {})

    def test_a_contender_that_wins_one_host_releases_it(self):
        owner = self.pair("owner")
        self.assertTrue(owner.acquire(), owner.last_error)
        os.kill(self.sandboxes[MASTER_NAME].lease()["holder_pid"], signal.SIGTERM)
        deadline = time.monotonic() + 30
        while not _lock_is_free(self.sandboxes[MASTER_NAME].lock_file):
            if time.monotonic() > deadline:
                self.fail("the terminated holder's kernel lock was not released")
            time.sleep(0.05)
        contender = self.pair("contender")
        self.assertFalse(contender.acquire(), "the contender took a pair with one host held")
        self.assertIn(lock_cases.HELD_SENTENCE, contender.last_error)
        self.assertTrue(
            _lock_is_free(self.sandboxes[MASTER_NAME].lock_file),
            "the contender kept the Master lock after being refused on the Worker",
        )

    def test_release_frees_both_hosts(self):
        lock = self.pair()
        self.assertTrue(lock.acquire(), lock.last_error)
        lock.release()
        self.assertTrue(_lock_is_free(self.sandboxes[MASTER_NAME].lock_file))
        self.assertTrue(_lock_is_free(self.sandboxes[WORKER_NAME].lock_file))
        self.assertFalse(lock.check_alive())
        self.assertEqual(lock.lease_tokens, {})

    def test_release_frees_a_holder_that_survives_a_terminated_client(self):
        # What ssh does: terminating the local client leaves the remote holder
        # running, so a release that only signals the client frees nothing and
        # the host stays locked for every later run.
        clients = {
            address: StubbornSSH(address, self.sandboxes[name])
            for address, name in (
                (MASTER_ADDRESS, MASTER_NAME), (WORKER_ADDRESS, WORKER_NAME),
            )
        }
        lock = preflight.RemotePairLock(
            clients[MASTER_ADDRESS], clients[WORKER_ADDRESS], run_id="stubborn",
        )
        self.addCleanup(lock.release)
        self.assertTrue(lock.acquire(), lock.last_error)
        self.assertFalse(_lock_is_free(self.sandboxes[MASTER_NAME].lock_file))
        lock.release()
        self.assertTrue(
            _lock_is_free(self.sandboxes[MASTER_NAME].lock_file),
            "the release signalled the client and not the holder, so the host stayed locked",
        )
        self.assertTrue(_lock_is_free(self.sandboxes[WORKER_NAME].lock_file))


#: A holder that owns the lock and writes the lease the validator reads, without
#: going through the product, so the validator can be asked about a lease whose
#: holder is known to this process.
LEASE_HOLDER = r"""
import fcntl, json, os, sys, time

lock_path, lease_path, token = sys.argv[1:4]
fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
with open(lease_path, "w", encoding="utf-8") as handle:
    json.dump({"run_id": "lease-test", "host": "local", "holder_pid": os.getpid(),
               "lease_token": token}, handle)
print("HELD", flush=True)
time.sleep(120)
"""


class TestLeaseContract(HolderCase, unittest.TestCase):
    """``modules/lock.sh``: what a token authorizes, and which variable wins."""

    def hold(self, token="a" * 64):
        process = subprocess.Popen(
            [sys.executable, "-c", LEASE_HOLDER,
             str(self.lock_file), str(self.lease_file), token],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: (process.kill(), process.wait()))
        self.assertEqual(process.stdout.readline().strip(), "HELD")
        return process

    def validate(self, token, lease=None, lock=None):
        completed = subprocess.run(
            ["bash", "-c",
             f'source {shlex.quote(str(REPO_ROOT / "modules" / "lock.sh"))}; '
             'validate_mutation_lease "$1" "$2" "$3"',
             "_", token, str(lease or self.lease_file), str(lock or self.lock_file)],
            capture_output=True, text=True, timeout=60,
        )
        return completed.returncode == 0

    def acquire(self, env_token, stdin_token):
        environment = {
            key: value for key, value in os.environ.items() if key != "GOWAVE_LEASE_TOKEN"
        }
        environment["MUTATION_LOCK_FILE"] = str(self.lock_file)
        environment["MUTATION_LEASE_FILE"] = str(self.lease_file)
        if env_token is not None:
            environment["GOWAVE_LEASE_TOKEN"] = env_token
        completed = subprocess.run(
            ["bash", "-c",
             f'source {shlex.quote(str(REPO_ROOT / "modules" / "lock.sh"))}; acquire_mutation_lock'],
            input=f"GOWAVE_LEASE: {stdin_token}\n", capture_output=True, text=True,
            env=environment, timeout=60,
        )
        return completed

    def test_a_live_holder_lease_is_accepted_and_a_wrong_token_is_not(self):
        process = self.hold("b" * 64)
        self.assertTrue(self.validate("b" * 64))
        self.assertFalse(self.validate("c" * 64))
        self.assertEqual(process.poll(), None)

    def test_a_dead_holders_lease_is_refused(self):
        process = self.hold("d" * 64)
        self.assertTrue(self.validate("d" * 64))
        process.kill()
        process.wait()
        self.assertFalse(self.validate("d" * 64), "a lease outlived the holder it names")

    def test_a_lease_whose_holder_holds_no_descriptor_is_refused(self):
        self.hold("e" * 64)
        # This process is alive and has no descriptor on the lock, which is what a
        # stale lease looks like: the pid answers, but nothing holds the flock.
        self.lease_file.write_text(
            json.dumps({
                "run_id": "lease-test", "host": "local",
                "holder_pid": os.getpid(), "lease_token": "f" * 64,
            }),
            encoding="utf-8",
        )
        self.assertFalse(self.validate("f" * 64))

    def test_the_environment_token_wins_over_the_stdin_line(self):
        self.hold("1" * 64)
        completed = self.acquire(env_token="2" * 64, stdin_token="1" * 64)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Invalid or stale mutation lock lease provided.", completed.stderr)

    def test_the_stdin_line_authorizes_when_no_token_is_exported(self):
        self.hold("3" * 64)
        completed = self.acquire(env_token=None, stdin_token="3" * 64)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("GOWAVE_LEASE_TOKEN", completed.stderr)


class TestRunStateGate(unittest.TestCase):
    """The verdict a phase reads, and the set of phases that read it."""

    def holder(self, alive):
        return types.SimpleNamespace(check_alive=lambda: alive)

    def test_a_held_pair_gates_every_phase(self):
        for phase in MUTATING_PHASES + ("verify", "snapshot"):
            with self.subTest(phase=phase):
                gate = pair_lock_gate(self.holder(True), phase)
                self.assertTrue(gate.ok)
                self.assertEqual(gate.status, "")

    def test_a_lost_pair_gates_every_mutating_phase_as_incomplete(self):
        for phase in MUTATING_PHASES:
            with self.subTest(phase=phase):
                gate = pair_lock_gate(self.holder(False), phase)
                self.assertFalse(gate.ok)
                self.assertEqual(gate.status, "INCOMPLETE")
                self.assertIn(phase, gate.error)
                self.assertIn("lock was lost", gate.error)

    def test_a_lost_pair_does_not_gate_a_read_only_phase(self):
        for phase in ("verify", "snapshot", "report"):
            with self.subTest(phase=phase):
                gate = pair_lock_gate(self.holder(False), phase)
                self.assertTrue(gate.ok)
                self.assertEqual(gate.status, "")

    def test_the_phases_a_lost_lock_stops_are_the_ones_that_change_a_host(self):
        self.assertEqual(set(MUTATING_PHASES), {"install", "traffic", "negative", "teardown"})


# --------------------------------------------------------------- the case drivers


class CaseHarness:
    """Two sandboxes and the product-shaped object the drivers read.

    A mixin, not a test class: the cases it prepares are run by
    ``TestLockDrivers`` and damaged by ``TestCaseGuards``.
    """

    def setUp(self):
        super().setUp()
        self.sandboxes = {
            MASTER_NAME: self.sandbox,
            WORKER_NAME: Sandbox(self.root, WORKER_NAME),
        }
        self.podman = LocalPodman(self.sandboxes)
        self.host = types.SimpleNamespace(
            plan=types.SimpleNamespace(target_ip=MASTER_ADDRESS, worker_ip=WORKER_ADDRESS),
            target_name=MASTER_NAME,
            worker_name=WORKER_NAME,
            podman=self.podman,
        )
        self.product = types.SimpleNamespace(topology=self.host)
        patcher = mock.patch.object(lock_cases, "_pair", self.pair_clients)
        patcher.start()
        self.addCleanup(patcher.stop)

    @contextlib.contextmanager
    def pair_clients(self, host):
        master = LocalSSH(host.plan.target_ip, self.sandboxes[host.target_name])
        worker = LocalSSH(host.plan.worker_ip, self.sandboxes[host.worker_name])
        try:
            yield master, worker
        finally:
            master.close()
            worker.close()

    def refusal(self, case_id, damage):
        """The case's own refusal sentence under one damage, or None if it passed."""
        with damage:
            try:
                CASES[case_id](self.product)
            except AssertionError as error:
                return str(error)
        return None


class TestLockDrivers(CaseHarness, HolderCase, unittest.TestCase):
    """The three drivers, run whole."""

    def test_the_three_cases_hold(self):
        for case_id, function in CASES.items():
            with self.subTest(case_id=case_id):
                facts = function(self.product)
                self.assertIsInstance(facts, dict)
                self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            facts = function(self.product)
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    sorted(facts), registry[case_id]["multi-node"]["evidence"],
                    f"{case_id} returns evidence the catalog does not record",
                )


def _damaged_holder(old, new):
    """The holder program with one clause replaced, proven to have been replaced."""
    script = preflight.LOCK_HOLDER_SCRIPT
    count = script.count(old)
    if count != 1:
        raise AssertionError(f"the anchor {old!r} occurs {count} times in the holder program")
    return script.replace(old, new)


MODE_CHECK = '''if stat.S_IMODE(info.st_mode) & 0o077:
    refuse("the lock file " + LOCK_PATH + " grants group or other access")'''

FLOCK = """try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    refuse("another process holds " + LOCK_PATH)"""

TOKEN = "token = secrets.token_hex(32)"


class TestCaseGuards(CaseHarness, HolderCase, unittest.TestCase):
    """Each guard, damaged on its own, refusing for its own reason."""

    def test_a_holder_that_skips_the_mode_check_fails_the_path_case(self):
        damage = mock.patch.object(
            preflight, "LOCK_HOLDER_SCRIPT",
            _damaged_holder(MODE_CHECK, ""),
        )
        self.assertIn(
            "was taken while",
            self.refusal(lock_cases.LOCK_PATH_CASE_ID, damage),
        )

    def test_a_holder_that_ignores_flock_fails_the_pair_case(self):
        damage = mock.patch.object(preflight, "LOCK_HOLDER_SCRIPT", _damaged_holder(FLOCK, ""))
        self.assertIn(
            "a second runner acquired the pair-wide lock",
            self.refusal(lock_cases.LOCK_CASE_ID, damage),
        )

    def test_a_holder_that_reuses_one_token_fails_the_pair_case(self):
        damage = mock.patch.object(
            preflight, "LOCK_HOLDER_SCRIPT",
            _damaged_holder(TOKEN, 'token = "0" * 64'),
        )
        self.assertIn(
            "was handed the previous holder's tokens",
            self.refusal(lock_cases.LOCK_CASE_ID, damage),
        )

    def test_a_holder_that_repairs_the_path_it_refuses_fails_the_path_case(self):
        # The holder removes the object it is about to refuse and then refuses with
        # the right sentence, so the sentence check passes and only the comparison
        # of the object before and after can catch it.
        repairing = MODE_CHECK.replace(
            "    refuse(",
            '    os.unlink(os.readlink("/proc/self/fd/" + str(dir_fd)) + "/" + LOCK_NAME) '
            "or refuse(",
            1,
        )
        damage = mock.patch.object(
            preflight, "LOCK_HOLDER_SCRIPT", _damaged_holder(MODE_CHECK, repairing),
        )
        self.assertIn(
            "was replaced or followed",
            self.refusal(lock_cases.LOCK_PATH_CASE_ID, damage),
        )

    def test_a_gate_that_accepts_a_lost_pair_fails_the_loss_case(self):
        damage = mock.patch.object(
            lock_cases, "pair_lock_gate",
            lambda _lock, _phase: types.SimpleNamespace(ok=True, status="", error=""),
        )
        self.assertIn(
            "rather than INCOMPLETE",
            self.refusal(lock_cases.LOCK_LOSS_CASE_ID, damage),
        )

    def test_a_lock_that_keeps_half_the_pair_fails_the_loss_case(self):
        leaked = []

        def stubborn(self):
            # The real class ends the half it won when the other host refuses. This
            # one leaves it running, which is what a pair held by a run that never
            # started looks like from the host.
            leaked.extend(self._procs)

        damage = mock.patch.object(lock_cases.RemotePairLock, "release", stubborn)
        try:
            sentence = self.refusal(lock_cases.LOCK_LOSS_CASE_ID, damage)
        finally:
            for process in leaked:
                with contextlib.suppress(OSError):
                    process.kill()
        self.assertIn("half the pair", sentence)

    def test_a_runner_that_never_notices_a_lost_session_fails_the_loss_case(self):
        damage = mock.patch.object(lock_cases.RemotePairLock, "check_alive", lambda _self: True)
        with mock.patch.object(
            lock_cases, "wait_until", lambda predicate, *_args, **_kwargs: predicate(),
        ):
            sentence = self.refusal(lock_cases.LOCK_LOSS_CASE_ID, damage)
        self.assertIn("terminated one", sentence)

    def test_a_validator_that_accepts_any_token_fails_the_pair_case(self):
        damage = mock.patch.object(lock_cases, "_validate_lease", lambda *_args, **_kwargs: True)
        self.assertIn(
            "still accepts the lease of a holder that released",
            self.refusal(lock_cases.LOCK_CASE_ID, damage),
        )


class TestOwnershipShapeCapability(CaseHarness, HolderCase, unittest.TestCase):
    """Whether the ownership shape can reach the check it is supposed to prove.

    With `fs.protected_regular=2` and a sticky, world-writable `/run/lock`, the
    holder's `open` refuses another user's file before it reads the owner, so the
    case would be reading a different sentence than the one it names. The probe
    repeats the holder's own open, and the evidence names the shapes it left out
    instead of counting them as refused.
    """

    def test_an_object_the_holder_can_open_reaches_the_ownership_check(self):
        self.lock_file.write_text("", encoding="utf-8")
        self.lock_file.chmod(0o600)
        self.assertTrue(lock_cases.ownership_shape_reachable(self.host, MASTER_NAME))

    def test_the_probe_opens_the_object_the_way_the_holder_does(self):
        # The probe predicts which check refuses the object, so it is only right
        # while it repeats the holder's own open: a holder that stops asking for
        # `O_CREAT`, or opens the directory differently, moves the sentence the
        # case reads without moving the decision that skipped it.
        holder = preflight.LOCK_HOLDER_SCRIPT
        for token in (
            "os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW",
            "os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW",
        ):
            with self.subTest(token=token):
                self.assertEqual(holder.count(token), 1, f"the holder does not open with {token!r}")
                self.assertEqual(
                    lock_cases._OPEN_PROBE.count(token), 1,
                    f"the probe does not open with {token!r}, so it answers a different "
                    "question than the one the holder's open answers",
                )

    @unittest.skipIf(
        os.geteuid() == 0,
        "root opens any object, so an unreadable one cannot be expressed here",
    )
    def test_an_object_the_runner_cannot_open_is_not_reachable(self):
        self.lock_file.write_text("", encoding="utf-8")
        self.lock_file.chmod(0o000)
        self.assertFalse(
            lock_cases.ownership_shape_reachable(self.host, MASTER_NAME),
            "the probe reports an unopenable object as reachable, so the ownership shape "
            "would be asserted against a refusal that names the open instead",
        )

    def test_a_non_regular_object_is_never_reachable(self):
        self.lock_file.mkdir()
        self.assertFalse(lock_cases.ownership_shape_reachable(self.host, MASTER_NAME))

    def test_a_shape_the_contour_cannot_express_is_named_not_counted(self):
        writing = lock_cases._write_shape

        def write(host, container, shape):
            # A regular, runner-owned file stands in for the foreign object: the
            # contours that can write the real shape skip it later, at the probe,
            # so the contract under test is the same on both.
            if shape != "a file owned by another user":
                return writing(host, container, shape)
            sandbox = self.sandboxes[container]
            sandbox.lock_file.write_text("", encoding="utf-8")
            sandbox.lock_file.chmod(0o600)
            return True

        with mock.patch.object(lock_cases, "_write_shape", write), mock.patch.object(
            lock_cases, "ownership_shape_reachable", lambda *_args: False,
        ):
            facts = CASES[lock_cases.LOCK_PATH_CASE_ID](self.product)

        skipped = json.loads(facts["shapes_skipped"])
        self.assertTrue(
            any("a file owned by another user" in entry for entry in skipped),
            f"the skipped ownership shape is not named in {skipped!r}: a smaller count of "
            "refusals would then read as a full sweep",
        )
        self.assertEqual(
            facts["shapes_refused"], 8,
            "a shape that was never exercised was counted as refused",
        )
        self.assertNotIn(
            "a file owned by another user", json.loads(facts["shape_sentences"]),
        )

    def test_a_directory_that_cannot_be_moved_aside_is_named_not_asserted(self):
        # `/run/lock` is a mount point inside a systemd container, so `mv` answers
        # EBUSY, and no host that mounts its lock directory can be handed the
        # symlinked-directory sentence. The case names that instead of failing on
        # a sentence nothing on that host can produce.
        original = self.podman.exec

        def refuse_move(name, argv, check=True, input_text=None, timeout=None):
            if any("lock.case" in str(part) and "mv " in str(part) for part in argv):
                return types.SimpleNamespace(
                    returncode=1, stdout="",
                    stderr="mv: cannot move '/run/lock' to '/run/lock.case': Device or resource busy",
                )
            return original(name, argv, check=check, input_text=input_text, timeout=timeout)

        with mock.patch.object(self.podman, "exec", refuse_move):
            facts = CASES[lock_cases.LOCK_PATH_CASE_ID](self.product)

        skipped = json.loads(facts["shapes_skipped"])
        self.assertTrue(
            any(entry.startswith(f"a symlinked lock directory on {MASTER_NAME}:")
                and "Device or resource busy" in entry for entry in skipped),
            f"the unmovable lock directory is not named in {skipped!r}",
        )
        self.assertEqual(
            facts["directory_symlink_refusal"], "",
            "a directory the host could not replace was reported as refused",
        )
        self.assertTrue(
            facts["directory_restored"],
            "a host that was never touched is reported as damaged",
        )
        for sandbox in self.sandboxes.values():
            self.assertTrue(
                sandbox.lock_dir.is_dir() and not sandbox.lock_dir.is_symlink(),
                "the lock directory is not the real directory it started as",
            )


# ------------------------------------------------------------------- the plumbing


LEASE_FORWARDING = 'GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}" \\'
DISPATCH = re.compile(r"gowave-node-auto\.sh\" remote_(payload|rollback)")
PAYLOAD_EXPORT = """printf 'export GOWAVE_LEASE_TOKEN=%q\\n' "${GOWAVE_WORKER_LEASE_TOKEN:-}" """


def _assert_dispatch_forwarding(text):
    """Every dispatch carries the Worker's own transit variable, five of five."""
    lines = text.splitlines()
    exports = [index for index, line in enumerate(lines) if line.strip() == LEASE_FORWARDING.strip()]
    dispatches = [index for index, line in enumerate(lines) if DISPATCH.search(line)]
    if len(exports) != 5 or len(dispatches) != 5:
        raise AssertionError(
            f"{len(exports)} lease-forwarding lines for {len(dispatches)} dispatches, and there "
            "are five dispatches: a rollback or deploy started without the Worker's lease can "
            "only be refused by the Worker's own lock"
        )
    for export, dispatch in zip(exports, dispatches):
        if dispatch != export + 1:
            raise AssertionError(
                f"the lease forwarding on line {export + 1} is not part of the dispatch on "
                f"line {dispatch + 1}"
            )


def _assert_payload_forwarding(text):
    """Both payload env blocks export the Worker's token as the lease, twice."""
    lines = text.splitlines()
    exports = [index for index, line in enumerate(lines) if line.strip() == PAYLOAD_EXPORT.strip()]
    if len(exports) != 2:
        raise AssertionError(
            f"{len(exports)} payload lease exports, expected 2 (deploy payload and rollback "
            "payload)"
        )
    for export in exports:
        following = "\n".join(lines[export:export + 40])
        if not re.search(r"cat <<'(RUNNER_FUNCS|ROLLBACK_REMOTE_SCRIPT)'", following):
            raise AssertionError(
                f"the payload lease export on line {export + 1} is not part of a streamed program"
            )


class RecordingSSH:
    """The one method ``deploy_worker`` uses, recorded, with canned answers."""

    def __init__(self, answers=()):
        self.calls = []
        self.answers = list(answers)

    def run(self, remote_cmd, input_data=None, timeout=60):
        self.calls.append({"cmd": remote_cmd, "input_data": input_data})
        for needle, result in self.answers:
            if needle in remote_cmd:
                return result
        return SSHResult(returncode=0, stdout="", stderr="")


def _assert_worker_lease_transport(calls, master_token, worker_token):
    """The Worker's token arrives as its own variable; the Master's rides stdin."""
    staged = [call for call in calls if "/run/live_vps_worker_lease" in call["cmd"] and
              "cat >" in call["cmd"]]
    if len(staged) != 1:
        raise AssertionError(f"the Worker lease was staged {len(staged)} times")
    if staged[0]["input_data"] != worker_token:
        raise AssertionError("the Worker lease was not delivered over stdin")
    dispatch = [call for call in calls if "strace -f -v" in call["cmd"]]
    if len(dispatch) != 1:
        raise AssertionError(f"the Worker dispatch ran {len(dispatch)} times")
    command = dispatch[0]["cmd"]
    if "GOWAVE_LEASE_TOKEN=" in command:
        raise AssertionError(
            "the dispatch exports GOWAVE_LEASE_TOKEN for the Worker's token: the product reads "
            "that variable first, so the Master's own command would validate the Worker's lease"
        )
    if f'GOWAVE_WORKER_LEASE_TOKEN="$(cat /run/live_vps_worker_lease)"' not in command:
        raise AssertionError("the dispatch does not read the staged Worker lease")
    if worker_token in command:
        raise AssertionError("the Worker's lease token reached argv")
    if dispatch[0]["input_data"] != f"GOWAVE_LEASE: {master_token}\n":
        raise AssertionError(
            f"the Master's dispatch carried {dispatch[0]['input_data']!r} on stdin"
        )
    if not any("rm -f /run/live_vps_worker_lease" in call["cmd"] for call in calls):
        raise AssertionError("the staged Worker lease was never removed")


class TestWorkerLeasePlumbing(unittest.TestCase):
    """The lease rides stdin into the Master and its own variable to the Worker."""

    def config(self):
        return types.SimpleNamespace(
            acme_mode="staging",
            ssh_key_path="/nonexistent/gowave-test-key",
            ssh_known_hosts="/nonexistent/gowave-test-known-hosts",
            worker_ssh_key_path=None,
            worker_known_hosts_path=None,
            worker_vision_domain=None,
            worker_ip=WORKER_ADDRESS,
            worker_domain="worker.example.test",
            worker_reality_domain="worker-reality.example.test",
            worker_ssh_user="root",
            worker_ssh_port=22,
            gowave_node_installer_commit="a" * 40,
            gowave_node_installer_sha256="b" * 64,
            gowave_node_version="v1.0.5",
            xray_server_version="26.11.9",
            reality_fingerprint="chrome",
        )

    def deploy(self, master_token="m" * 64, worker_token="w" * 64):
        master = RecordingSSH()
        worker = RecordingSSH()
        with mock.patch.object(deployment, "ensure_strace_on_master", lambda _ssh: (True, "")), \
                mock.patch.object(deployment, "run_master_acceptance_fixtures", lambda _ssh: (True, "")):
            deployment.deploy_worker(
                master, worker, self.config(),
                lease_token=master_token, worker_lease_token=worker_token,
            )
        return master.calls

    def test_the_two_leases_travel_on_different_channels(self):
        calls = self.deploy()
        _assert_worker_lease_transport(calls, "m" * 64, "w" * 64)

    def test_a_lease_in_the_master_variable_is_refused(self):
        calls = self.deploy()
        damaged = [dict(call) for call in calls]
        for call in damaged:
            if "strace -f -v" in call["cmd"]:
                call["cmd"] = call["cmd"].replace(
                    'GOWAVE_WORKER_LEASE_TOKEN="$(cat', 'GOWAVE_LEASE_TOKEN="$(cat')
        with self.assertRaises(AssertionError) as caught:
            _assert_worker_lease_transport(damaged, "m" * 64, "w" * 64)
        self.assertIn("GOWAVE_LEASE_TOKEN", str(caught.exception))

    def test_a_worker_token_in_argv_is_refused(self):
        calls = self.deploy()
        damaged = [dict(call) for call in calls]
        for call in damaged:
            if "strace -f -v" in call["cmd"]:
                call["cmd"] = call["cmd"] + " " + "w" * 64
        with self.assertRaises(AssertionError) as caught:
            _assert_worker_lease_transport(damaged, "m" * 64, "w" * 64)
        self.assertIn("reached argv", str(caught.exception))

    def test_every_shell_dispatch_forwards_the_worker_lease(self):
        text = (REPO_ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        _assert_dispatch_forwarding(text)
        damaged = text.replace(LEASE_FORWARDING + "\n", "", 1)
        with self.assertRaises(AssertionError):
            _assert_dispatch_forwarding(damaged)

    def test_both_payloads_export_the_worker_lease(self):
        text = (REPO_ROOT / "gowave-node-auto.sh").read_text(encoding="utf-8")
        _assert_payload_forwarding(text)
        damaged = text.replace(PAYLOAD_EXPORT.rstrip() + "\n", "", 1)
        with self.assertRaises(AssertionError):
            _assert_payload_forwarding(damaged)


def _function_body(path: Path, name: str) -> str:
    """A top-level bash function, from its definition line to its closing brace."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for start, line in enumerate(lines):
        if line.rstrip("\n") == f"{name}() {{":
            break
    else:
        raise AssertionError(f"{path.name} defines no {name}()")
    for end in range(start + 1, len(lines)):
        if lines[end].rstrip("\n") == "}":
            return "".join(lines[start:end + 1])
    raise AssertionError(f"{name}() in {path.name} never closes")


def _lock_call_offsets(text: str):
    """Where each mutation-lock acquisition sits in a bash script.

    The ``acquire_lock()`` definition and the one line of its body are skipped: a
    call site is what an entry point runs, and counting the wrapper would let the
    first assertion below be satisfied by a script that takes the lock nowhere.
    """
    wrapper = text.find("acquire_lock() {")
    wrapper_end = text.find("\n}", wrapper) if wrapper >= 0 else -1
    offsets = []
    position = 0
    for line in text.splitlines(keepends=True):
        inside_wrapper = 0 <= wrapper <= position <= wrapper_end
        stripped = line.strip()
        if not inside_wrapper:
            for name in ("acquire_lock", "acquire_mutation_lock"):
                if stripped == name or stripped.startswith(f"{name} "):
                    offsets.append(position)
                    break
        position += len(line)
    return offsets


#: Each management entry point the case drives, the script that prints its
#: marker, and the source text that composes the marker. A sentence printed
#: before the script took the lock would be a refusal about something else, so
#: the test below reads the order rather than the case's own prose.
ENTRY_POINT_SOURCES = {
    "install": ("gowave-auto.sh", [
        ("Invalid DNS hostname: invalid", "Invalid DNS hostname: {domain}"),
    ]),
    "node add": ("gowave-auto.sh", [
        ("Usage: gowave-auto.sh node add", "Usage: gowave-auto.sh node add"),
    ]),
    "node rollback": ("gowave-auto.sh", [
        ("Usage: gowave-auto.sh node rollback", "Usage: gowave-auto.sh node rollback"),
    ]),
    "node reapply": ("gowave-auto.sh", [
        ("Usage: gowave-auto.sh node reapply", "Usage: gowave-auto.sh node reapply"),
    ]),
    "domain-change": ("gowave-auto.sh", [
        ("Usage: gowave-auto.sh domain-change", "Usage: gowave-auto.sh domain-change"),
    ]),
    "channel": ("modules/recovery.sh", [
        ("GoWave is already on channel", "GoWave is already on channel '$target_channel'."),
        ("Error: /opt/gowave/.env not found", "Error: $env_file not found"),
    ]),
    "uninstall": ("gowave-auto.sh", [
        ("WARNING: This will remove GoWave Auto NGINX managed components.",
         "WARNING: This will remove GoWave Auto NGINX managed components."),
    ]),
    "backup restore": ("assets/backup/gowave-backup.sh", [
        ("==> Initiating Restore from", "==> Initiating Restore from"),
    ]),
}

#: The commands as an operator spells them. The case exists to prove the shipped
#: CLI is refused by the lock, so the spelling is part of what it claims.
ENTRY_POINT_ARGV = {
    "install": ["install", "invalid", "invalid", "ops@example.com"],
    "node add": ["node", "add"],
    "node rollback": ["node", "rollback"],
    "node reapply": ["node", "reapply"],
    "domain-change": ["domain-change"],
    "channel": ["channel", "stable"],
    "uninstall": ["uninstall"],
    "backup restore": ["restore", lock_cases.INVALID_ARCHIVE],
}


class RecordingPodman:
    """A transport that records the command instead of running it."""

    def __init__(self):
        self.calls = []

    def exec(self, name, argv, check=True, input_text=None, timeout=None):
        self.calls.append({
            "container": name, "argv": list(argv), "check": check,
            "input_text": input_text, "timeout": timeout,
        })
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


class TestCliEntryPointTable(unittest.TestCase):
    """The eight entry points, their spelling, and the lock each marker follows."""

    def test_the_table_names_eight_distinct_entry_points_in_order(self):
        entries = lock_cases._entry_points("stable")
        self.assertEqual([entry["label"] for entry in entries],
                         list(ENTRY_POINT_ARGV))
        self.assertEqual(len({entry["marker"] for entry in entries}), len(entries))
        for entry in entries:
            with self.subTest(label=entry["label"]):
                self.assertEqual(entry["argv"], ENTRY_POINT_ARGV[entry["label"]])
                self.assertTrue(entry["marker"])

    def test_the_channel_entry_point_reads_the_hosts_own_channel(self):
        installed = {entry["label"]: entry for entry in lock_cases._entry_points("dev")}
        self.assertEqual(installed["channel"]["argv"], ["channel", "dev"])
        self.assertEqual(installed["channel"]["marker"],
                         "GoWave is already on channel 'dev'.")
        bare = {entry["label"]: entry for entry in lock_cases._entry_points(None)}
        self.assertEqual(bare["channel"]["argv"], ["channel", "stable"])
        self.assertEqual(bare["channel"]["marker"], "Error: /opt/gowave/.env not found")

    def test_every_marker_is_printed_after_a_lock_call_in_its_script(self):
        for label, (relative, pairs) in ENTRY_POINT_SOURCES.items():
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            calls = _lock_call_offsets(text)
            with self.subTest(label=label):
                self.assertTrue(calls, f"{relative} takes the mutation lock nowhere")
                for _marker, source_text in pairs:
                    with self.subTest(label=label, source=source_text):
                        found = text.find(source_text)
                        self.assertGreaterEqual(
                            found, 0,
                            f"{relative} no longer prints {source_text!r}",
                        )
                        before = [offset for offset in calls if offset < found]
                        self.assertTrue(
                            before,
                            f"{relative} prints {source_text!r} before it takes the lock "
                            "anywhere, so the refusal would be about something else",
                        )

    def test_the_markers_the_case_waits_for_are_the_ones_the_scripts_print(self):
        printed = set()
        for channel in ("stable", None):
            printed.update(entry["marker"] for entry in lock_cases._entry_points(channel))
        composed = {marker for _relative, pairs in ENTRY_POINT_SOURCES.values()
                    for marker, _source in pairs}
        # The installed-channel marker interpolates the host's channel, so the
        # table above pins only its stable instance; compare the whole sentence.
        printed = {marker for marker in printed
                   if not marker.startswith("GoWave is already on channel")}
        self.assertEqual(sorted(printed - composed), [])

    def test_the_restore_checks_its_archive_before_it_takes_the_lock(self):
        # The case names a garbage file rather than a missing one: a missing
        # archive is refused before the lock, and the marker this case waits for
        # would never be printed, so the refusal could not be attributed to the
        # lock at all.
        body = _function_body(
            REPO_ROOT / "assets" / "backup" / "gowave-backup.sh", "cmd_restore")
        check_at = body.find("Archive $archive not found")
        lock_at = body.find("acquire_mutation_lock")
        marker_at = body.find("==> Initiating Restore from")
        self.assertGreaterEqual(check_at, 0)
        self.assertGreaterEqual(lock_at, 0)
        self.assertGreaterEqual(marker_at, 0)
        self.assertLess(check_at, lock_at)
        self.assertLess(lock_at, marker_at)


class TestCliCommandConstruction(unittest.TestCase):
    """How the case spells the command it hands ``podman exec``."""

    def run_cli(self, argv, **arguments):
        podman = RecordingPodman()
        lock_cases._run_cli(
            types.SimpleNamespace(podman=podman), MASTER_NAME, list(argv), **arguments)
        self.assertEqual(len(podman.calls), 1)
        return podman.calls[0]

    def test_a_lease_is_read_by_the_child_shell_and_never_spliced_into_argv(self):
        call = self.run_cli(["domain-change"], token_file=lock_cases.NESTED_TOKEN_FILE)
        self.assertEqual(call["argv"][:2], ["bash", "-c"])
        self.assertEqual(len(call["argv"]), 3, "the command grew an argument beside bash -c")
        command = call["argv"][2]
        self.assertIn(
            f'GOWAVE_LEASE_TOKEN="$(cat {lock_cases.NESTED_TOKEN_FILE})"', command)
        self.assertTrue(command.startswith("cd /repo && "))
        self.assertIn("exec bash ./gowave-auto.sh domain-change", command)
        self.assertTrue(command.endswith("</dev/null"))

    def test_a_lease_fed_on_stdin_keeps_stdin_attached(self):
        call = self.run_cli(["domain-change"], stdin_text="GOWAVE_LEASE: token\n")
        self.assertNotIn("</dev/null", call["argv"][2])
        self.assertEqual(call["input_text"], "GOWAVE_LEASE: token\n")

    def test_a_command_with_no_stdin_of_its_own_reads_from_dev_null(self):
        call = self.run_cli(["uninstall"])
        self.assertTrue(call["argv"][2].endswith("</dev/null"))
        self.assertIsNone(call["input_text"])

    def test_an_argument_with_a_space_or_a_dollar_is_passed_as_one_word(self):
        call = self.run_cli(["install", "a b", "$(id)"])
        command = call["argv"][2]
        self.assertIn("'a b'", command)
        self.assertIn("'$(id)'", command)


class TestLockRegistration(unittest.TestCase):
    """The five ids are registered, catalogued, evidenced and mapped."""

    def test_each_id_is_registered_on_the_multi_node_contour_only(self):
        registry = catalog.driver_registry()
        for case_id, function in ALL_CASES.items():
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), {"multi-node"})
                self.assertEqual(
                    registry[case_id]["multi-node"]["driver"],
                    f"lock_cases:{function.__name__}",
                )

    def test_each_registered_case_is_handed_the_product_not_the_run_context(self):
        # The runner calls ``case.run(context)``, while a driver needs the two
        # hosts. Every other Multi-Node case closes over its product in a lambda
        # for that reason; a raw function reference would be handed the run
        # context and fail at the first host attribute instead of here.
        from tools.podman_e2e import multi_node

        stub = types.SimpleNamespace(context=types.SimpleNamespace(topology="multi-node"))
        suite = {case.id: case for case in multi_node.cases(stub)}
        context = types.SimpleNamespace(topology="multi-node")
        for case_id, function in ALL_CASES.items():
            with self.subTest(case_id=case_id):
                received = []
                with mock.patch.object(
                    lock_cases, function.__name__,
                    lambda product: received.append(product) or {},
                ):
                    suite[case_id].run(context)
                self.assertEqual(len(received), 1, f"{case_id} did not call its driver once")
                self.assertIsNot(
                    received[0], context,
                    f"{case_id} handed its driver the run context, which has no "
                    "containers to drive",
                )
                self.assertIsInstance(received[0], multi_node.MultiNodeProduct)

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in ALL_CASES:
            with self.subTest(case_id=case_id):
                self.assertEqual(entries[case_id]["driver_status"], "implemented")
                self.assertEqual(entries[case_id]["drivers"], registry[case_id])

    def test_every_case_is_named_by_exactly_one_behavior(self):
        self.assertEqual(catalog.coverage_audit(catalog.load_catalog()), [])

    def test_every_id_is_mapped_to_a_requirement(self):
        table = yaml.safe_load(
            (REPO_ROOT / "tests" / "cases" / "traceability.yaml").read_text(encoding="utf-8"))
        mapped = set()
        for row in table["requirements"]:
            for scenario in row["scenarios"]:
                mapped.update(scenario.get("cases") or [])
        for entry in table.get("cases_by_requirement") or []:
            mapped.update(entry.get("cases") or [])
        self.assertEqual(sorted(set(ALL_CASES) - mapped), [])
