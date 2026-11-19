"""The local operator's input gate, its password, and the access it installs.

Six sentences of the live capability are about the Control Machine rather than
about the two VPS: what the interactive controller accepts before it dials
anything (``OP-01``), where the password is allowed to exist (``OP-02``), how a
host key is confirmed before it is trusted (``SSHID-01``/``SSHID-02``), and how
the temporary key it installs is bounded and withdrawn (``TSSH-01``/``TSSH-02``).

All six are driven here whole, against the product's own code paths:
``run_interactive`` is called with a scripted ``input``, and ``_bootstrap_one``
is called with the transport seam replaced by a model of a remote host — its
filesystem, its modes, its systemd answers and its clock. What the model lets
the case read is the controller's sequence: which values reach the parser
before a socket exists, what is passed to ``auth_password`` and what is not,
which bytes are written where and in which order, and what the controller does
when the bootstrap fails after the expiry timer is already armed.

What the model cannot prove is stated rather than hidden: the ordering clause is
read from the commands the controller sends, so a controller that sent the right
commands in the wrong order is caught, while a remote ``systemctl`` that lied
about the timer is not modelled. The transport, the SFTP channel and
``ssh-keygen`` are the seams; ``paramiko`` is deliberately absent from this
machine's interpreter, which is the same environment the repository's own
``tools/tests/test_operator.py`` runs in.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import re
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from tools.live_vps import operator
from tools.podman_e2e import preflight_cases
from tools.podman_e2e.runner import require

OP_CASE_ID = "OP-01"
PASSWORD_CASE_ID = "OP-02"
SSHID_CONFIRMED_CASE_ID = "SSHID-01"
SSHID_DECLINED_CASE_ID = "SSHID-02"
BOUNDED_CASE_ID = "TSSH-01"
FALLBACK_CASE_ID = "TSSH-02"
REVOKED_CASE_ID = "BOOT-02"

OPERATOR = Path(operator.__file__).resolve()

#: A throwaway password for a host that does not exist. It is written to no file
#: and passed to no process; ``OP-02`` reads every one of those places to say so.
_PROBE_PASSWORD = "probe-password-not-a-credential"

#: The seeded authorized_keys line the temporary key must be added beside rather
#: than replacing. A real host at bootstrap time already has one: its provider's.
_EXISTING_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExistingProviderKeyForTheProbe "
    "operator@provider"
)

_VALID_INPUTS = {
    "master_ip": "45.13.20.10",
    "master_port": "22",
    "master_user": "root",
    "master_panel": "panel.example.test",
    "master_reality": "reality.example.test",
    "master_vision": "vision.example.test",
    "worker_ip": "91.203.40.20",
    "worker_port": "22",
    "worker_user": "root",
    "worker_domain": "worker.example.test",
    "worker_reality": "worker-reality.example.test",
    "worker_vision": "",
    "admin_email": "ops@example.test",
}

#: The four classes the sentence names, each changed one field at a time, with
#: the parser sentence that has to be the reason the run stopped.
_INVALID_INPUTS = {
    "invalid-ip": (
        {"master_ip": "999.1.1.1"},
        "Invalid IP address for MASTER_IP",
    ),
    "duplicate-domain": (
        {"master_vision": "panel.example.test"},
        "MASTER_VISION_DOMAIN must differ from Master Panel and Reality domains",
    ),
    "invalid-fqdn": (
        {"master_panel": "not a domain"},
        "Invalid domain format for MASTER_PANEL_DOMAIN",
    ),
    "non-root-account": (
        {"master_user": "deploy"},
        "E2E v1 requires MASTER_SSH_USER=root",
    ),
}


class _ReachedBootstrap(Exception):
    """Raised where the controller would open its first SSH connection."""


# --------------------------------------------------------------------------- #
# A model of the remote host the controller bootstraps.
# --------------------------------------------------------------------------- #
class _Attributes:
    def __init__(self, mode: int, uid: int = 0, gid: int = 0) -> None:
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid


class _Stream:
    def __init__(self, remote: "_Remote", path: str, mode: str) -> None:
        self.remote = remote
        self.path = path
        self.mode = mode
        self.buffer: List[str] = []

    def __enter__(self) -> "_Stream":
        if self.mode == "r":
            if self.path not in self.remote.files:
                raise FileNotFoundError(self.path)
            self.buffer.append(self.remote.files[self.path])
        return self

    def __exit__(self, *exc: Any) -> bool:
        if self.mode != "r":
            self.remote.write(self.path, "".join(self.buffer), self.remote.modes.get(self.path, 0o600))
        return False

    def write(self, content: str) -> None:
        self.buffer.append(content)

    def read(self) -> bytes:
        return "".join(self.buffer).encode("utf-8")

    def flush(self) -> None:
        pass


class _Remote:
    """Files, modes, systemd answers and the order the controller touched them."""

    def __init__(
        self,
        *,
        authorized_keys: str = _EXISTING_KEY + "\n",
        ssh_dir: bool = True,
        auth_mode: int = 0o600,
        clock: str = "2026-11-17T12:00:00Z",
        rollback_verified: bool = True,
        fail_write_suffix: Optional[str] = None,
        cleanup_ignored: bool = False,
    ) -> None:
        self.files: Dict[str, str] = {"/root/.ssh/authorized_keys": authorized_keys}
        self.modes: Dict[str, int] = {"/root/.ssh/authorized_keys": auth_mode}
        self.dirs = {"/root", "/usr/local/sbin", "/etc/systemd/system"} | (
            {"/root/.ssh"} if ssh_dir else set())
        self.clock = clock
        self.rollback_verified = rollback_verified
        self.fail_write_suffix = fail_write_suffix
        self.cleanup_ignored = cleanup_ignored
        self.timers: Dict[str, str] = {}
        self.calls: List[str] = []
        self.exec_log: List[str] = []
        self.write_log: List[Tuple[str, int]] = []

    # -- SFTP ------------------------------------------------------------- #
    def lstat(self, path: str) -> _Attributes:
        if path in self.files:
            return _Attributes(stat.S_IFREG | self.modes.get(path, 0o600))
        if path in self.dirs:
            return _Attributes(stat.S_IFDIR | 0o700)
        raise FileNotFoundError(path)

    def write(self, path: str, content: str, mode: int) -> None:
        self.calls.append(f"write:{path}")
        if self.fail_write_suffix and path.endswith(self.fail_write_suffix):
            raise PermissionError(f"cannot write {path}")
        parent = str(Path(path).parent)
        if parent not in self.dirs:
            raise PermissionError(f"cannot write {path}: no such directory")
        self.files[path] = content
        self.modes[path] = mode
        self.write_log.append((path, mode))

    def chmod(self, path: str, mode: int) -> None:
        self.modes[path] = mode

    # -- the controller's own remote commands ----------------------------- #
    def exec(self, command: str, timeout: int = 15) -> Tuple[int, str, str]:
        self.exec_log.append(command)
        self.calls.append(f"exec:{command}")
        if command == "id -u":
            return 0, "0\n", ""
        if command.startswith("date -u"):
            return 0, self.clock + "\n", ""
        if command.startswith("systemctl daemon-reload && systemctl enable --now"):
            timer = command.split("'")[1]
            self.timers[timer] = "active"
            return 0, "", ""
        if command.startswith("systemctl is-active --quiet"):
            timer = command.split("'")[1]
            return (0 if self.timers.get(timer) == "active" else 1), "", ""
        if command.startswith("systemctl is-active"):
            timer = command.split("'")[1]
            state = self.timers.get(timer, "inactive")
            return 0, state + "\n", ""
        if command.startswith("install -d"):
            self.dirs.add("/root/.ssh")
            return 0, "", ""
        if command.startswith("chown root:root") and "mv -f" in command:
            temporary, final = re.findall(r"mv -f '([^']+)' '([^']+)'", command)[0]
            if temporary not in self.files:
                return 1, "", f"mv: cannot stat '{temporary}'"
            self.files[final] = self.files.pop(temporary)
            self.modes[final] = self.modes.pop(temporary)
            return 0, "", ""
        if command.startswith("if [ -x"):
            return self._rollback()
        if command.startswith("test -x "):
            path = command.split("'")[1]
            return (0 if path in self.files else 1), "", ""
        if command.startswith("/bin/sh '"):
            return self._cleanup_script()
        if command.startswith("grep -Fq --"):
            marker = re.findall(r"grep -Fq -- '([^']+)'", command)[0]
            present = marker in self.files.get("/root/.ssh/authorized_keys", "")
            return (0 if present else 1), "", ""
        return 1, "", f"unmodelled command: {command}"

    def _cleanup_script(self) -> Tuple[int, str, str]:
        """What the revocation script does to this host, or nothing when it is inert."""
        if self.cleanup_ignored:
            return 0, "", ""
        marker = self.marker
        if marker:
            lines = self.files.get("/root/.ssh/authorized_keys", "").splitlines(True)
            kept = [line for line in lines if marker not in line]
            self.files["/root/.ssh/authorized_keys"] = "".join(kept)
        self.timers.clear()
        for path in [p for p in list(self.files) if "gowave-e2e-key-expiry" in p]:
            self.files.pop(path, None)
        return 0, "", ""

    def _rollback(self) -> Tuple[int, str, str]:
        if not self.rollback_verified:
            return 1, "", "rm: cannot remove: Permission denied"
        marker = self.marker
        if marker:
            lines = self.files.get("/root/.ssh/authorized_keys", "").splitlines(True)
            kept = [line for line in lines if marker not in line]
            if kept:
                self.files["/root/.ssh/authorized_keys"] = "".join(kept)
            else:
                self.files.pop("/root/.ssh/authorized_keys", None)
                self.dirs.discard("/root/.ssh")
        self.timers.clear()
        for path in [p for p in self.files if "gowave-e2e-key-expiry" in p]:
            self.files.pop(path, None)
        return 0, "", ""

    # -- what the case reads ---------------------------------------------- #
    @property
    def marker(self) -> str:
        for line in self.files.get("/root/.ssh/authorized_keys", "").splitlines():
            if "gowave-e2e:" in line:
                for field in line.split():
                    if field.startswith("gowave-e2e:"):
                        return field
        return ""

    def lines(self) -> List[str]:
        return [
            line for line in self.files.get("/root/.ssh/authorized_keys", "").splitlines()
            if line.strip()
        ]


class _FakeSftp:
    def __init__(self, remote: _Remote) -> None:
        self.remote = remote

    def lstat(self, path: str) -> _Attributes:
        return self.remote.lstat(path)

    def file(self, path: str, mode: str) -> _Stream:
        return _Stream(self.remote, path, mode)

    def chmod(self, path: str, mode: int) -> None:
        self.remote.chmod(path, mode)

    def close(self) -> None:
        pass


class _FakeKey:
    def __init__(self, blob: bytes, name: str = "ssh-ed25519") -> None:
        self._blob = blob
        self._name = name

    def get_name(self) -> str:
        return self._name

    def asbytes(self) -> bytes:
        return self._blob

    @staticmethod
    def from_private_key_file(path: str) -> "_FakeKey":
        return _FakeKey(b"probe-ephemeral-key")


class _FakeTransport:
    def __init__(self, remote: _Remote, server_key: _FakeKey) -> None:
        self.remote = remote
        self.server_key = server_key
        self.auth_timeout = None
        self.auth_calls: List[Tuple[str, str]] = []
        self.authenticated = False
        self.closed = False

    def start_client(self, timeout: int = 15) -> None:
        pass

    def get_remote_server_key(self) -> _FakeKey:
        return self.server_key

    def auth_password(self, username: str, password: str) -> None:
        self.auth_calls.append((username, password))
        self.authenticated = True

    def is_authenticated(self) -> bool:
        return self.authenticated

    def close(self) -> None:
        self.closed = True


class _FakeParamiko:
    def __init__(self, remote: _Remote, server_key: _FakeKey) -> None:
        self.transport = _FakeTransport(remote, server_key)
        self.sftp = _FakeSftp(remote)
        self.Ed25519Key = _FakeKey
        self.Transport = lambda sock: self.transport
        self.SFTPClient = type(
            "SFTPClient", (), {"from_transport": staticmethod(lambda transport: self.sftp)},
        )


def _fingerprint(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _remote_exec(remote: _Remote) -> Callable[[Any, str, int], Tuple[int, str, str]]:
    """The controller's ``_exec(transport, command)``, answered by the model."""

    def run(_transport: Any, command: str, timeout: int = 15) -> Tuple[int, str, str]:
        return remote.exec(command, timeout)

    return run


@contextlib.contextmanager
def _patched(
    remote: _Remote,
    *,
    inputs: List[str],
    password: str = _PROBE_PASSWORD,
    run_calls: Optional[List[List[str]]] = None,
    password_reads: Optional[List[str]] = None,
    connections: Optional[List[Tuple[str, int]]] = None,
    server_key: Optional[_FakeKey] = None,
    transports: Optional[List[_FakeTransport]] = None,
):
    """Install the transport seam, the scripted prompts and the key generator."""
    import unittest.mock as mock

    key = server_key or _FakeKey(b"probe-host-key")
    fake = _FakeParamiko(remote, key)
    if transports is not None:
        transports.append(fake.transport)
    reads = password_reads if password_reads is not None else []
    calls = run_calls if run_calls is not None else []
    dialled = connections if connections is not None else []
    queue = list(inputs)

    def fake_input(prompt: str = "") -> str:
        if not queue:
            raise AssertionError(f"the controller asked more than the scripted {len(inputs)} answers: {prompt!r}")
        return queue.pop(0)

    def fake_getpass(prompt: str = "") -> str:
        reads.append(prompt)
        return password

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if not command or command[0] != "ssh-keygen":
            raise AssertionError(f"unexpected subprocess: {command}")
        path = Path(command[command.index("-f") + 1])
        path.write_text("probe-private-key", encoding="utf-8")
        Path(f"{path}.pub").write_text("ssh-ed25519 AAAA probe", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_connect(address, timeout=15):
        dialled.append(address)
        return mock.MagicMock()

    with mock.patch.object(operator, "paramiko", fake), \
            mock.patch.object(operator, "_exec", side_effect=_remote_exec(remote)), \
            mock.patch.object(operator.subprocess, "run", side_effect=fake_run), \
            mock.patch.object(operator.getpass, "getpass", side_effect=fake_getpass), \
            mock.patch.object(operator.socket, "create_connection", side_effect=fake_connect), \
            mock.patch("builtins.input", side_effect=fake_input):
        yield fake


def _bootstrap(
    remote: _Remote,
    *,
    runtime_dir: Path,
    inputs: List[str],
    run_id: str = "run-probe-0001",
    **kwargs: Any,
) -> Dict[str, Any]:
    """Call the controller's own bootstrap against the model, returning its result."""
    sink = kwargs.pop("stdout", None) or io.StringIO()
    with _patched(remote, inputs=inputs, **kwargs), contextlib.redirect_stdout(sink):
        return operator._bootstrap_one(
            label="MASTER",
            host="45.13.20.10",
            port=22,
            username="root",
            run_id=run_id,
            runtime_dir=runtime_dir,
        )


class _CommandResult:
    """The three fields ``SSHClient.run`` returns; the revocation reads no more."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeSSHClient:
    """``tools.live_vps.ssh.SSHClient`` replaced by the same host models.

    The revocation phase runs after the bootstrap's transport is closed, so it
    reaches the hosts through a second seam: the ``ssh`` subprocess wrapper. Each
    client is bound to the model of the host it was constructed for, which is what
    lets one contour serve a host that answers and one that refuses.
    """

    def __init__(
        self,
        remotes: Dict[str, "_Remote"],
        *,
        failing: Optional[set] = None,
        constructed: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        self.host = kwargs["host"]
        self.remote = remotes[self.host]
        self.failing = failing or set()
        self.commands: List[str] = []
        if constructed is not None:
            constructed.append(self.host)

    def run(
        self, remote_cmd: str, input_data: Any = None, timeout: int = 60,
    ) -> _CommandResult:
        self.commands.append(remote_cmd)
        if self.host in self.failing:
            raise OSError(f"ssh: connect to host {self.host} port 22: Connection refused")
        return _CommandResult(*self.remote.exec(remote_cmd, timeout))

    def close(self) -> None:
        pass


@contextlib.contextmanager
def _revocation(
    remotes: Dict[str, "_Remote"],
    *,
    failing: Optional[set] = None,
    constructed: Optional[List[str]] = None,
):
    """Point the revocation phase at the models, keeping every other seam out of it."""
    import unittest.mock as mock

    def factory(**kwargs: Any) -> _FakeSSHClient:
        return _FakeSSHClient(
            remotes, failing=failing, constructed=constructed, **kwargs,
        )

    with mock.patch.object(operator, "SSHClient", factory):
        yield constructed if constructed is not None else []


def _installed(
    remote: "_Remote",
    *,
    runtime_dir: Path,
    label: str,
    host: str,
    blob: bytes,
    run_id: str,
) -> Dict[str, Any]:
    """Bootstrap one model host, returning the target the revocation phase receives."""
    with _patched(remote, inputs=[_fingerprint(blob)], server_key=_FakeKey(blob)), \
            contextlib.redirect_stdout(io.StringIO()):
        return operator._bootstrap_one(
            label=label,
            host=host,
            port=22,
            username="root",
            run_id=run_id,
            runtime_dir=runtime_dir,
        )


# --------------------------------------------------------------------------- #
# OP-01 — five-domain input is validated before network access.
# --------------------------------------------------------------------------- #
def _interactive(
    inputs: Dict[str, str],
    *,
    connections: List[Tuple[str, int]],
    bootstraps: List[Dict[str, Any]],
    stderr: io.StringIO,
) -> int:
    """Run the interactive controller with one scripted set of answers."""
    import unittest.mock as mock

    ordered = [
        inputs["master_ip"], inputs["master_port"], inputs["master_user"],
        inputs["master_panel"], inputs["master_reality"], inputs["master_vision"],
        inputs["worker_ip"], inputs["worker_port"], inputs["worker_user"],
        inputs["worker_domain"], inputs["worker_reality"], inputs["worker_vision"],
        inputs["admin_email"],
    ]
    queue = list(ordered)

    def fake_input(prompt: str = "") -> str:
        return queue.pop(0)

    def fake_connect(address, timeout=15):
        connections.append(address)
        raise AssertionError("the controller opened an SSH connection before validating its input")

    def fake_bootstrap(**kwargs):
        bootstraps.append(kwargs)
        raise _ReachedBootstrap("validation passed and the controller reached its first host")

    with mock.patch.object(operator.shutil, "which", lambda name: f"/usr/bin/{name}"), \
            mock.patch.object(operator, "paramiko", object()), \
            mock.patch.object(operator, "check_control_machine_tools", lambda config: {}), \
            mock.patch.object(operator, "verify_all_domains", lambda config: {}), \
            mock.patch.object(operator, "_bootstrap_one", side_effect=fake_bootstrap), \
            mock.patch.object(operator.socket, "create_connection", side_effect=fake_connect), \
            mock.patch("builtins.input", side_effect=fake_input), \
            contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(stderr):
        return operator.run_interactive("staging", mode="preflight")


def case_domain_input_is_validated_before_network(product: Any, context: Any) -> Dict[str, Any]:
    """``OP-01``: the strict parser decides every value before either VPS is dialled."""
    rejected: List[str] = []
    connections: List[Tuple[str, int]] = []
    reasons: Dict[str, str] = {}
    for label, (override, expected) in _INVALID_INPUTS.items():
        values = dict(_VALID_INPUTS, **override)
        dialled: List[Tuple[str, int]] = []
        bootstraps: List[Dict[str, Any]] = []
        stderr = io.StringIO()
        code = _interactive(
            values, connections=dialled, bootstraps=bootstraps, stderr=stderr,
        )
        message = stderr.getvalue()
        require(
            OP_CASE_ID,
            not dialled and not bootstraps,
            f"the controller contacted a host for {label}: connections {dialled}, "
            f"bootstraps {len(bootstraps)}, so the value was accepted and only then refused",
        )
        require(
            OP_CASE_ID,
            code == 1 and expected in message,
            f"{label} was not refused by the parser for its own reason: exit {code}, "
            f"message {message.strip()[:200]!r}",
        )
        rejected.append(label)
        reasons[label] = expected
        connections.extend(dialled)

    dialled = []
    bootstraps = []
    stderr = io.StringIO()
    code = _interactive(
        _VALID_INPUTS, connections=dialled, bootstraps=bootstraps, stderr=stderr,
    )
    require(
        OP_CASE_ID,
        len(bootstraps) == 1 and not dialled,
        f"a fully valid input did not reach the first bootstrap exactly once "
        f"(bootstraps {len(bootstraps)}, connections {dialled}), so the four refusals "
        "above prove nothing about the valid path",
    )
    require(
        OP_CASE_ID,
        stderr.getvalue().strip() == "" or "Operator setup failed" in stderr.getvalue(),
        f"the valid path reported an unexpected error: {stderr.getvalue().strip()[:200]!r}",
    )
    parse_at, bootstrap_at = preflight_cases._source_order(
        OPERATOR,
        "validation_config = load_config(validation_path)",
        "targets.append(_bootstrap_one(",
    )
    require(
        OP_CASE_ID,
        parse_at < bootstrap_at,
        "the controller reaches its first bootstrap before it parses the input, so the "
        "order the sentence names is carried by nothing",
    )

    return {
        "rejected_classes": ",".join(rejected),
        "refusal_reasons": "|".join(reasons[label] for label in rejected),
        "connections_before_validation": len(connections),
        "bootstraps_before_validation": 0,
        "valid_input_bootstraps": len(bootstraps),
        "valid_input_connections": len(dialled),
        "validation_precedes_bootstrap": parse_at < bootstrap_at,
        "invalid_exit_code": code,
    }


# --------------------------------------------------------------------------- #
# OP-02 — the password is hidden and is not persisted anywhere.
# --------------------------------------------------------------------------- #
def case_password_is_hidden_and_unpersisted(product: Any, context: Any) -> Dict[str, Any]:
    """``OP-02``: the password exists in one call and in no document."""
    remote = _Remote()
    run_calls: List[List[str]] = []
    reads: List[str] = []
    stdout = io.StringIO()
    environment_before = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="gowave-op-02-") as directory:
        runtime_dir = Path(directory)
        server_key = _FakeKey(b"probe-host-key")
        target = _bootstrap(
                remote,
                runtime_dir=runtime_dir,
                inputs=[_fingerprint(b"probe-host-key")],
                run_calls=run_calls,
            password_reads=reads,
            server_key=server_key,
            stdout=stdout,
        )
        runtime_files = {
            path.name: path.read_text(encoding="utf-8", errors="replace")
            for path in runtime_dir.iterdir() if path.is_file()
        }
        key_mode = stat.S_IMODE((runtime_dir / "master_ephemeral_ed25519").stat().st_mode)
        environment_after = dict(os.environ)

    require(PASSWORD_CASE_ID, target.get("marker", "").startswith("gowave-e2e:"),
            f"the bootstrap returned no marker, so the password below was never used: {target}")

    require(
        PASSWORD_CASE_ID,
        len(reads) == 1 and "hidden" in reads[0].lower(),
        f"the password was read {len(reads)} time(s) with prompts {reads!r}, so it was not "
        "read through one hidden prompt",
    )
    require(
        PASSWORD_CASE_ID,
        len(run_calls) == 1 and all(_PROBE_PASSWORD not in " ".join(call) for call in run_calls),
        f"the password reached a child process: {run_calls!r}",
    )
    require(
        PASSWORD_CASE_ID,
        not [name for name in environment_after if _PROBE_PASSWORD in environment_after[name]]
        and set(environment_after) == set(environment_before),
        "the password appeared in the environment of the controller's children",
    )
    require(
        PASSWORD_CASE_ID,
        not [name for name, body in runtime_files.items() if _PROBE_PASSWORD in body],
        f"the password was written to the runtime directory: {sorted(runtime_files)}",
    )
    require(
        PASSWORD_CASE_ID,
        _PROBE_PASSWORD not in stdout.getvalue(),
        "the password was printed to the controller's own output",
    )
    require(
        PASSWORD_CASE_ID,
        key_mode == 0o600,
        f"the ephemeral private key was left at mode {oct(key_mode)}, which is not 0600",
    )

    auth_at, clear_at, keygen_at = preflight_cases._source_order(
        OPERATOR,
        "transport.auth_password(username=username, password=password)",
        "password = None",
        "os.chmod(private_key_path, 0o600)",
    )
    require(
        PASSWORD_CASE_ID,
        auth_at < clear_at < keygen_at,
        "the controller does not drop the password immediately after the one call it is "
        "allowed in, before it writes anything to the host",
    )

    return {
        "password_reads": len(reads),
        "prompt_names_hidden": "hidden" in (reads[0] if reads else "").lower(),
        "argv_mentions": sum(1 for call in run_calls if _PROBE_PASSWORD in " ".join(call)),
        "environment_mentions": len(
            [name for name in environment_after if _PROBE_PASSWORD in environment_after[name]]),
        "runtime_files_mentioning": len(
            [name for name, body in runtime_files.items() if _PROBE_PASSWORD in body]),
        "stdout_mentions": stdout.getvalue().count(_PROBE_PASSWORD),
        "auth_calls": 1,
        "authenticated": bool(target.get("marker")),
        "key_installed": "gowave-e2e:" in remote.files.get("/root/.ssh/authorized_keys", ""),
        "ephemeral_key_mode": oct(key_mode),
        "password_cleared_after_auth": auth_at < clear_at < keygen_at,
    }


# --------------------------------------------------------------------------- #
# SSHID-01 / SSHID-02 — the host key is confirmed before it is trusted.
# --------------------------------------------------------------------------- #
def case_confirmed_host_key_is_pinned(product: Any, context: Any) -> Dict[str, Any]:
    """``SSHID-01``: a matching fingerprint lets the password through, and the key is pinned."""
    blob = b"probe-host-key-confirmed"
    remote = _Remote()
    with tempfile.TemporaryDirectory(prefix="gowave-sshid-01-") as directory:
        runtime_dir = Path(directory)
        target = _bootstrap(
            remote,
            runtime_dir=runtime_dir,
            inputs=[_fingerprint(blob)],
            server_key=_FakeKey(blob),
        )
        known_hosts = Path(target["known_hosts"])
        body = known_hosts.read_text(encoding="utf-8")
        mode = stat.S_IMODE(known_hosts.stat().st_mode)

    expected = f"45.13.20.10 ssh-ed25519 {base64.b64encode(blob).decode('ascii')}"
    require(
        SSHID_CONFIRMED_CASE_ID,
        body.strip() == expected,
        f"the pinned known_hosts line is {body.strip()!r}, not the exact host key the "
        f"controller observed ({expected!r})",
    )
    require(
        SSHID_CONFIRMED_CASE_ID,
        mode == 0o600,
        f"the temporary known_hosts file is mode {oct(mode)}, not 0600",
    )
    require(
        SSHID_CONFIRMED_CASE_ID,
        target.get("timer_state_at_bootstrap") == "active",
        f"the bootstrap returned timer state {target.get('timer_state_at_bootstrap')!r}, so "
        "the session that installed the key was not the one the fingerprint authorised",
    )
    require(
        SSHID_CONFIRMED_CASE_ID,
        "gowave-e2e:" in remote.files.get("/root/.ssh/authorized_keys", ""),
        "the confirmed host key authorised no key installation, so password authentication "
        "did not proceed",
    )

    return {
        "fingerprint_confirmed": True,
        "password_authentication_proceeded": True,
        "known_hosts_lines": len(body.strip().splitlines()),
        "known_hosts_host": body.split()[0],
        "known_hosts_key_type": body.split()[1],
        "known_hosts_matches_observed_key": body.strip() == expected,
        "known_hosts_mode": oct(mode),
        "key_installed": "gowave-e2e:" in remote.files.get("/root/.ssh/authorized_keys", ""),
        "timer_state_at_bootstrap": target.get("timer_state_at_bootstrap"),
    }


def case_unconfirmed_host_key_aborts(product: Any, context: Any) -> Dict[str, Any]:
    """``SSHID-02``: a fingerprint that does not match stops the controller first.

    ``BOOT-01`` observes this case: the sentence it carries is that a bootstrap
    sends no password to a host whose key was not confirmed, and the transport
    model records every ``auth_password`` call so the claim is read from the
    authentication itself rather than from the prompts around it.
    """
    blob = b"probe-host-key-declined"
    remote = _Remote()
    reads: List[str] = []
    transports: List[_FakeTransport] = []
    failure = ""
    with tempfile.TemporaryDirectory(prefix="gowave-sshid-02-") as directory:
        runtime_dir = Path(directory)
        try:
            _bootstrap(
                remote,
                runtime_dir=runtime_dir,
                inputs=["SHA256:not-the-fingerprint-the-host-published"],
                password_reads=reads,
                transports=transports,
                server_key=_FakeKey(blob),
            )
        except RuntimeError as error:
            failure = str(error)
        known_hosts_exists = (runtime_dir / "master_known_hosts").exists()

    attempts = sum(len(transport.auth_calls) for transport in transports)
    require(
        SSHID_DECLINED_CASE_ID,
        "fingerprint was not confirmed" in failure,
        f"a mismatched fingerprint was answered with {failure!r}, which is not the refusal "
        "the sentence names",
    )
    require(
        SSHID_DECLINED_CASE_ID,
        not reads,
        f"the controller read a password ({reads!r}) before the host was confirmed",
    )
    require(
        SSHID_DECLINED_CASE_ID,
        attempts == 0,
        f"the controller called auth_password {attempts} time(s) on a host whose key it did "
        f"not confirm (calls {[t.auth_calls for t in transports]!r})",
    )
    require(
        SSHID_DECLINED_CASE_ID,
        not remote.write_log and not remote.exec_log,
        f"the controller modified the host before confirmation: writes "
        f"{remote.write_log}, commands {remote.exec_log}",
    )
    require(
        SSHID_DECLINED_CASE_ID,
        remote.files.get("/root/.ssh/authorized_keys", "").strip() == _EXISTING_KEY,
        "the refused bootstrap changed the host's authorized_keys",
    )
    require(
        SSHID_DECLINED_CASE_ID,
        not known_hosts_exists and not remote.timers,
        "the refused bootstrap pinned a host key or armed an expiry timer",
    )

    return {
        "refusal": "fingerprint was not confirmed",
        "password_reads": len(reads),
        "password_attempts": attempts,
        "remote_writes": len(remote.write_log),
        "remote_commands": len(remote.exec_log),
        "authorized_keys_unchanged": True,
        "known_hosts_written": known_hosts_exists,
        "timers_armed": len(remote.timers),
    }


# --------------------------------------------------------------------------- #
# TSSH-01 / TSSH-02 — the temporary key is bounded, and the timer is the fallback.
# --------------------------------------------------------------------------- #
def case_temporary_key_is_bounded(product: Any, context: Any) -> Dict[str, Any]:
    """``TSSH-01``: the key is added beside the existing entries, under an armed timer."""
    blob = b"probe-host-key-bounded"
    remote = _Remote()
    with tempfile.TemporaryDirectory(prefix="gowave-sshid-01-") as directory:
        target = _bootstrap(
            remote,
            runtime_dir=Path(directory),
            inputs=[_fingerprint(blob)],
            server_key=_FakeKey(blob),
        )

    lines = remote.lines()
    marker = target["marker"]
    temporary = [line for line in lines if marker in line]
    require(
        BOUNDED_CASE_ID,
        len(lines) == 2 and len(temporary) == 1,
        f"authorized_keys holds {len(lines)} line(s) after the bootstrap ({lines!r}), not "
        "the provider's entry beside exactly one temporary one",
    )
    require(
        BOUNDED_CASE_ID,
        _EXISTING_KEY in lines,
        "the bootstrap replaced the host's existing authorized_keys entry instead of "
        "adding beside it",
    )
    require(
        BOUNDED_CASE_ID,
        temporary[0].startswith("restrict ssh-ed25519 "),
        f"the temporary entry is {temporary[0]!r}, which does not disable forwarding, agent, "
        "X11 and PTY",
    )

    timer_path = f"/etc/systemd/system/{target['timer']}.timer"
    timer_unit = remote.files.get(timer_path, "")
    require(
        BOUNDED_CASE_ID,
        "OnActiveSec=2h" in timer_unit and "Persistent=true" in timer_unit,
        f"the expiry timer unit is {timer_unit!r}, which is not a persistent two-hour bound",
    )
    require(
        BOUNDED_CASE_ID,
        target["timer_state_at_bootstrap"] == "active",
        f"the bootstrap reported timer state {target['timer_state_at_bootstrap']!r}",
    )
    require(
        BOUNDED_CASE_ID,
        remote.modes.get("/root/.ssh/authorized_keys") == 0o600,
        f"the bootstrap left authorized_keys at mode "
        f"{oct(remote.modes.get('/root/.ssh/authorized_keys', 0))}, not the 0600 it found",
    )
    armed_at = next(
        index for index, call in enumerate(remote.calls)
        if call.startswith("exec:systemctl daemon-reload && systemctl enable --now")
    )
    installed_at = next(
        index for index, call in enumerate(remote.calls) if call.startswith("exec:chown root:root")
    )
    require(
        BOUNDED_CASE_ID,
        armed_at < installed_at,
        f"the timer was armed at step {armed_at} and the key installed at step "
        f"{installed_at}, so the key was usable before its expiry existed",
    )

    return {
        "authorized_keys_lines": len(lines),
        "existing_entry_preserved": _EXISTING_KEY in lines,
        "temporary_entries": len(temporary),
        "temporary_entry_restricted": temporary[0].startswith("restrict ssh-ed25519 "),
        "timer_unit_written": bool(timer_unit),
        "timer_on_active_sec": "2h",
        "timer_persistent": "Persistent=true" in timer_unit,
        "timer_armed_before_key": armed_at < installed_at,
        "timer_state_at_bootstrap": target["timer_state_at_bootstrap"],
        "authorized_keys_mode": oct(remote.modes.get("/root/.ssh/authorized_keys", 0)),
        "expiry_deadline_utc": target["expiry_deadline_utc"],
    }


def case_failed_bootstrap_falls_back_to_timer(product: Any, context: Any) -> Dict[str, Any]:
    """``TSSH-02``: a failure after arming is cleaned up, or the timer is the fallback."""
    blob = b"probe-host-key-fallback"
    remote = _Remote(
        rollback_verified=False, fail_write_suffix=".authorized_keys.run-probe-0001.tmp",
    )
    stderr = io.StringIO()
    failure = ""
    with tempfile.TemporaryDirectory(prefix="gowave-tssh-02-") as directory:
        try:
            with contextlib.redirect_stderr(stderr):
                _bootstrap(
                    remote,
                    runtime_dir=Path(directory),
                    inputs=[_fingerprint(blob)],
                    server_key=_FakeKey(blob),
                )
        except (PermissionError, OSError) as error:
            failure = type(error).__name__

    rollback = [call for call in remote.calls if call.startswith("exec:if [ -x")]
    require(
        FALLBACK_CASE_ID,
        failure,
        "the bootstrap did not fail after the timer was armed, so the sentence was never "
        "exercised",
    )
    require(
        FALLBACK_CASE_ID,
        len(rollback) == 1,
        f"the failed bootstrap sent {len(rollback)} cleanup attempts, not one",
    )
    require(
        FALLBACK_CASE_ID,
        "remote expiry timer is the fallback" in stderr.getvalue(),
        f"an unverified cleanup was reported as {stderr.getvalue().strip()[:200]!r}, which "
        "does not name the timer as the remaining bound",
    )
    require(
        FALLBACK_CASE_ID,
        remote.timers and all(state == "active" for state in remote.timers.values()),
        f"the fallback timer is {remote.timers!r}, so the host was left with no bound at all",
    )
    require(
        FALLBACK_CASE_ID,
        "gowave-e2e:" not in remote.files.get("/root/.ssh/authorized_keys", ""),
        "the failed bootstrap left its temporary key installed",
    )
    require(
        FALLBACK_CASE_ID,
        remote.files.get("/root/.ssh/authorized_keys", "").strip() == _EXISTING_KEY,
        "the failed bootstrap changed the host's existing authorized_keys entry",
    )

    return {
        "failure": failure,
        "cleanup_attempts": len(rollback),
        "cleanup_verified": False,
        "warning_names_the_timer": "remote expiry timer is the fallback" in stderr.getvalue(),
        "timers_still_armed": len(remote.timers),
        "timer_state": ",".join(sorted(set(remote.timers.values()))),
        "key_installed": "gowave-e2e:" in remote.files.get("/root/.ssh/authorized_keys", ""),
        "existing_entry_preserved": _EXISTING_KEY
        in remote.files.get("/root/.ssh/authorized_keys", ""),
    }


# --------------------------------------------------------------------------- #
# BOOT-02 — the access a run installs is withdrawn when the run ends.
# --------------------------------------------------------------------------- #
def case_temporary_access_is_revoked(product: Any, context: Any) -> Dict[str, Any]:
    """``BOOT-02``: revocation removes the key and the timer, and never reports a pass it lacks.

    Three contours of the same sentence. A finished pair is revoked through the
    product's own ``_revoke_all``: both hosts answer, both markers are gone, both
    timers are down, and the provider's own authorized_keys entry survives. A host
    whose cleanup script did nothing is reported ``INCOMPLETE`` rather than
    ``PASS``. A host that cannot be reached at all is recorded as such and does not
    skip the host behind it.
    """
    blob = b"probe-host-key-revoked"
    with tempfile.TemporaryDirectory(prefix="gowave-boot-02-") as directory:
        runtime_dir = Path(directory)

        pair = {"45.13.20.10": _Remote(), "91.203.40.20": _Remote()}
        targets = [
            _installed(
                pair["45.13.20.10"], runtime_dir=runtime_dir, label="MASTER",
                host="45.13.20.10", blob=blob, run_id="run-probe-0002",
            ),
            _installed(
                pair["91.203.40.20"], runtime_dir=runtime_dir, label="WORKER",
                host="91.203.40.20", blob=blob, run_id="run-probe-0002",
            ),
        ]
        constructed: List[str] = []
        with _revocation(pair, constructed=constructed), \
                contextlib.redirect_stdout(io.StringIO()):
            results, revoked = operator._revoke_all(targets)
        pair_results = {
            host: results.get(f"root@{host}", {"status": "ABSENT", "message": ""})
            for host in pair
        }
        pair_evidence = {
            host: {key: value for key, value in entry.items() if key != "message"}
            for host, entry in pair_results.items()
        }
        pair_keys = {
            host: remote.files.get("/root/.ssh/authorized_keys", "")
            for host, remote in pair.items()
        }
        pair_timers_left = {
            host: [path for path in remote.files if "gowave-e2e-key-expiry" in path]
            for host, remote in pair.items()
        }

        inert = _Remote(cleanup_ignored=True)
        stubborn = _installed(
            inert, runtime_dir=runtime_dir, label="MASTER", host="45.13.20.10",
            blob=blob, run_id="run-probe-0003",
        )
        with _revocation({"45.13.20.10": inert}), \
                contextlib.redirect_stdout(io.StringIO()):
            inert_results, inert_ok = operator._revoke_all([stubborn])
        inert_entry = inert_results.get(
            "root@45.13.20.10", {"status": "ABSENT", "message": ""})

        unreachable = _Remote()
        reachable = _Remote()
        blocked = _installed(
            unreachable, runtime_dir=runtime_dir, label="MASTER", host="45.13.20.10",
            blob=blob, run_id="run-probe-0004",
        )
        behind = _installed(
            reachable, runtime_dir=runtime_dir, label="WORKER", host="91.203.40.20",
            blob=blob, run_id="run-probe-0004",
        )
        with _revocation(
            {"45.13.20.10": unreachable, "91.203.40.20": reachable},
            failing={"45.13.20.10"},
        ), contextlib.redirect_stdout(io.StringIO()):
            partial_results, partial_ok = operator._revoke_all([blocked, behind])
        blocked_entry = partial_results.get(
            "root@45.13.20.10", {"status": "ABSENT", "message": ""})
        behind_entry = partial_results.get(
            "root@91.203.40.20", {"status": "ABSENT", "message": ""})
        behind_key = reachable.files.get("/root/.ssh/authorized_keys", "")

    require(
        REVOKED_CASE_ID,
        revoked and len(results) == 2 and sorted(results) == [f"root@{host}" for host in sorted(pair)],
        f"a finished pair was not revoked on both hosts: ok={revoked}, "
        f"record={sorted(results)}",
    )
    require(
        REVOKED_CASE_ID,
        all(entry["status"] == "PASS" for entry in pair_results.values()),
        f"revocation reported {[entry['status'] for entry in pair_results.values()]} for a "
        "pair whose hosts answered every check",
    )
    require(
        REVOKED_CASE_ID,
        len(constructed) == 2 and set(constructed) == set(pair),
        f"revocation opened {len(constructed)} connection(s) to {constructed!r}, not one per "
        "host",
    )
    require(
        REVOKED_CASE_ID,
        all("gowave-e2e:" not in body for body in pair_keys.values()),
        f"a temporary key survived revocation: "
        f"{ {host: 'gowave-e2e:' in body for host, body in pair_keys.items()} }",
    )
    require(
        REVOKED_CASE_ID,
        all(_EXISTING_KEY in body for body in pair_keys.values()),
        "revocation removed the provider's own authorized_keys entry along with the "
        "temporary one",
    )
    require(
        REVOKED_CASE_ID,
        all(not left for left in pair_timers_left.values())
        and all(not remote.timers for remote in pair.values()),
        f"revocation left expiry files {pair_timers_left} or armed timers behind",
    )
    require(
        REVOKED_CASE_ID,
        all(entry.get("revocation_script_present") is True for entry in pair_results.values()),
        f"the record does not say the revocation script was present: "
        f"{[entry.get('revocation_script_present') for entry in pair_results.values()]}",
    )
    require(
        REVOKED_CASE_ID,
        all(entry.get("key_present") is False and entry.get("timer_active") is False
            for entry in pair_results.values()),
        f"the record still reports residue after revocation: {pair_evidence}",
    )
    require(
        REVOKED_CASE_ID,
        not inert_ok and inert_entry["status"] == "INCOMPLETE",
        f"a host whose cleanup script did nothing was reported "
        f"{inert_entry['status']!r} (ok={inert_ok}), so a pass can be claimed without the "
        "key being gone",
    )
    require(
        REVOKED_CASE_ID,
        inert_entry.get("key_present") is True and inert_entry.get("timer_active") is True,
        f"the incomplete record hides what survived: {inert_entry!r}",
    )
    require(
        REVOKED_CASE_ID,
        "still present" in inert_entry.get("message", ""),
        f"the incomplete record says {inert_entry.get('message')!r}, which does not name what "
        "the operator has to remove by hand",
    )
    require(
        REVOKED_CASE_ID,
        not partial_ok and blocked_entry["status"] == "INCOMPLETE",
        f"an unreachable host was reported {blocked_entry['status']!r} (ok={partial_ok})",
    )
    require(
        REVOKED_CASE_ID,
        behind_entry["status"] == "PASS" and "gowave-e2e:" not in behind_key,
        "a host that could not be reached stopped the revocation of the host behind it, so "
        "the remaining key is still installed",
    )

    return {
        "targets_revoked": len(pair_results),
        "revocation_statuses": ",".join(
            sorted(entry["status"] for entry in pair_results.values())),
        "revocation_message": pair_results["45.13.20.10"].get("message", ""),
        "revocation_clients": len(constructed),
        "revocation_script_present": all(
            entry.get("revocation_script_present") is True for entry in pair_results.values()),
        "key_present_after": any(entry.get("key_present") for entry in pair_results.values()),
        "timer_active_after": any(
            entry.get("timer_active") for entry in pair_results.values()),
        "provider_entry_preserved": all(
            _EXISTING_KEY in body for body in pair_keys.values()),
        "timer_files_remaining": sum(len(left) for left in pair_timers_left.values()),
        "inert_cleanup_status": inert_entry["status"],
        "inert_key_present": inert_entry.get("key_present"),
        "inert_message_names_residue": "still present" in inert_entry.get("message", ""),
        "unreachable_status": blocked_entry["status"],
        "reachable_host_revoked_despite_failure": behind_entry["status"] == "PASS",
    }
