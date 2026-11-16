"""The pair-wide lock is a kernel lock held by a session, not a file that exists.

``openspec/specs/live-vps-e2e/spec.md`` §Pair-Wide Run Locking and §Shared
Mutation Lock Across All Management Entry Points describe a lock another runner
cannot take while it is held, a run that stops mutating the moment a lock-holder
session dies, and a path that is refused instead of followed. Each of those is a
fact about a real ``flock`` on a real host, so the cases here drive the product's
own ``RemotePairLock`` over real SSH into the two containers this contour created
and read the product's own lease validator out of ``modules/lock.sh``.

What is not a VPS is the host: the Master and the Worker are the same containers
the rest of this contour installs, reached from the Control Machine at their
control-network addresses. Everything the sentences are about is real — the
holder is a separate process on the host that owns a kernel lock, the lease is
the file that process published, and a second runner is a second process
competing for the same inode. A case that damaged the lock path repairs it in a
``finally`` before the next case runs, and each refusal is asserted together with
the object still being the object it was.
"""
from __future__ import annotations

import contextlib
import json
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from tools.live_vps.preflight import RemotePairLock
from tools.live_vps.runstate import MUTATING_PHASES, pair_lock_gate
from tools.live_vps.ssh import SSHClient
from tools.podman_e2e.podman import wait_until
from tools.podman_e2e.runner import CaseBlocked, require

LOCK_CASE_ID = "MN-LOCK"
LOCK_LOSS_CASE_ID = "MN-LOCK-LOSS"
LOCK_PATH_CASE_ID = "MN-LOCK-PATH"
CLI_CASE_ID = "MN-LOCK-CLI"
NESTED_CASE_ID = "MN-LOCK-NESTED"

#: The canonical paths ``modules/lock.sh`` and the holder agree on.
LOCK_PATH = "/run/lock/gowave-managed-mutation.lock"
LEASE_PATH = "/run/lock/gowave-mutation-lease.json"
LOCK_DIR = "/run/lock"
LOCK_NAME = "gowave-managed-mutation.lock"

SSH_TIMEOUT_SECONDS = 120
#: A terminated holder is observed by the runner as a dead child, which takes one
#: poll of the session it owns; the deadline is generous because the container's
#: own `kill` is delivered through `podman exec`.
HOLDER_STOP_TIMEOUT_SECONDS = 60

#: What the runner says when another process owns the lock. Pinned as a sentence
#: rather than a substring of the path: the operator's next action is to find the
#: other runner, and a refusal that does not say the lock is held does not say so.
HELD_SENTENCE = f"another process holds {LOCK_PATH}"

#: What ``gowave-auto.sh`` itself says when the lock is occupied. Pinned as a
#: sentence rather than a substring: an operator who reads it knows the host is
#: owned by another run, and a command that failed for an unrelated reason does
#: not say this at all.
CLI_HELD_SENTENCE = f"Another process currently holds the mutation lock ({LOCK_PATH})."

#: What a command says when it was handed a lease that no longer authorizes it.
#: Distinct from the sentence above on purpose: being refused for holding nothing
#: and being refused for holding the wrong thing are different operator problems.
CLI_STALE_SENTENCE = "Invalid or stale mutation lock lease provided."

#: An archive that exists so ``cmd_restore`` gets past its own existence check,
#: and that is not a GoWave archive so nothing it contains could ever be applied.
INVALID_ARCHIVE = "/tmp/gowave-invalid-archive.tar.gz"

#: The file the nested command reads its lease from. A token handed to a child as
#: an argument would be authority in every process list on the host, so it is
#: written at mode 0600 and read by the child's own shell.
NESTED_TOKEN_FILE = "/tmp/gowave-nested-lease-token"

CLI_TIMEOUT_SECONDS = 180

#: Every file a management command could rewrite, read as a digest set. A command
#: that was refused has to leave all of them byte-identical, including the ones
#: that are absent: a command that created one mutated the host by existing.
_SNAPSHOT_PATHS = (
    "/opt/gowave/.env",
    "/opt/gowave/state.json",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/gowave-*.conf",
    "/etc/nginx/stream-enabled/gowave-*.conf",
    "/etc/systemd/system/gowave.service",
    "/etc/systemd/system/gowave-node.service",
    "/etc/systemd/system/gowave-recover.service",
    "/etc/systemd/system/gowave-recover-provision.service",
    "/etc/systemd/system/bbr-load.service",
)

_SNAPSHOT_SCRIPT = r"""
import glob, hashlib, json, sys

digests = {}
for pattern in sys.argv[1:]:
    matches = sorted(glob.glob(pattern))
    if not matches:
        digests[pattern] = "absent"
    for path in matches:
        try:
            with open(path, "rb") as handle:
                digests[path] = hashlib.sha256(handle.read()).hexdigest()
        except OSError as error:
            digests[path] = f"unreadable:{error.errno}"
print(json.dumps(digests, sort_keys=True))
"""

_LOCK_FILES_SCRIPT = (
    "import glob, json; print(json.dumps(sorted(glob.glob('/run/lock/*gowave*'))))"
)

#: The object a refused acquisition must leave exactly as it found it. Read with
#: `lstat`, so a symlink is reported as a symlink and never as its target.
_OBJECT_SCRIPT = r"""
import json, os, stat, sys

path = sys.argv[1]
try:
    info = os.lstat(path)
except FileNotFoundError:
    print(json.dumps({"exists": False}))
    sys.exit(0)

if stat.S_ISLNK(info.st_mode):
    kind = "symlink"
elif stat.S_ISDIR(info.st_mode):
    kind = "directory"
elif stat.S_ISFIFO(info.st_mode):
    kind = "fifo"
elif stat.S_ISREG(info.st_mode):
    kind = "regular"
else:
    kind = "other"

print(json.dumps({
    "exists": True,
    "kind": kind,
    "mode": oct(stat.S_IMODE(info.st_mode)),
    "uid": info.st_uid,
    "inode": info.st_ino,
    "target": os.readlink(path) if kind == "symlink" else "",
}))
"""

#: The product's own validator, sourced from the copy the run staged in the
#: container. The token arrives on stdin: a lease is authority, and authority in
#: argv is authority in every process list on the host.
_LEASE_VALIDATOR = (
    "IFS= read -r GOWAVE_CANDIDATE_TOKEN; "
    f"source /repo/modules/lock.sh; "
    'if validate_mutation_lease "$GOWAVE_CANDIDATE_TOKEN" "{lease}" "{lock}"; '
    "then echo VALID; else echo INVALID; fi"
)


def _topology(product: Any) -> Any:
    """The two hosts this contour created, or a block naming what is missing."""
    host = getattr(product, "topology", None)
    if host is None:
        raise CaseBlocked(
            f"{LOCK_CASE_ID}: this case needs the two hosts the run creates, and no "
            "topology has been created yet"
        )
    return host


def _containers(host: Any) -> Tuple[str, str]:
    return host.target_name, host.worker_name


def _addresses(host: Any) -> Tuple[str, str]:
    return host.plan.target_ip, host.plan.worker_ip


def _container_for(host: Any, address: str) -> str:
    master_address, worker_address = _addresses(host)
    return host.target_name if address == master_address else host.worker_name


def _address_for(host: Any, container: str) -> str:
    """The address a refusal names, so a sentence can be attributed to its host."""
    return dict(zip(_containers(host), _addresses(host)))[container]


@contextlib.contextmanager
def _pair(host: Any) -> Iterator[Tuple[SSHClient, SSHClient]]:
    """Two root SSH clients into the containers, with a pinned host key each.

    The key, the ``known_hosts`` entry and the private directory holding both are
    created for this case and removed with it. Nothing is learned from an
    unauthenticated ``ssh-keyscan``: each host key is read from the host's own
    filesystem, which is the trusted local control plane in this contour.
    """
    with tempfile.TemporaryDirectory(prefix="gowave-podman-lock-") as directory:
        root = Path(directory)
        key = root / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True, capture_output=True, timeout=60,
        )
        key.chmod(0o600)
        public = Path(f"{key}.pub").read_text(encoding="utf-8").strip()

        known_hosts = root / "known_hosts"
        entries: List[str] = []
        for container, address in zip(_containers(host), _addresses(host)):
            host.podman.exec(
                container,
                ["bash", "-c",
                 "umask 077; mkdir -p /root/.ssh; chmod 0700 /root/.ssh; "
                 "systemctl is-active --quiet ssh.service || "
                 "{ ssh-keygen -A >/dev/null 2>&1; systemctl start ssh.service; }"],
                timeout=SSH_TIMEOUT_SECONDS,
            )
            host.podman.exec(
                container,
                ["bash", "-c",
                 "umask 077; cat >> /root/.ssh/authorized_keys; "
                 "chmod 0600 /root/.ssh/authorized_keys"],
                input_text=public + "\n",
                timeout=SSH_TIMEOUT_SECONDS,
            )
            host_key = host.podman.exec(
                container, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
                timeout=SSH_TIMEOUT_SECONDS,
            ).stdout.strip()
            if not host_key.startswith("ssh-ed25519 "):
                raise AssertionError(
                    f"{LOCK_CASE_ID}: {container} has no ed25519 host key to pin, so no "
                    "SSH session could be authenticated at all"
                )
            entries.append(f"{address} {host_key}")
        known_hosts.write_text("\n".join(entries) + "\n", encoding="utf-8")
        known_hosts.chmod(0o600)

        # One TCP connection per host, never a multiplexed channel: the sentence
        # these cases read is about a session that can be lost on its own.
        master = SSHClient(
            host=_addresses(host)[0], port=22, user="root",
            key_path=key, known_hosts=known_hosts, multiplex=False,
        )
        worker = SSHClient(
            host=_addresses(host)[1], port=22, user="root",
            key_path=key, known_hosts=known_hosts, multiplex=False,
        )
        try:
            yield master, worker
        finally:
            master.close()
            worker.close()


def _lease(host: Any, container: str) -> Dict[str, Any]:
    """The lease the holder published on one host, or an empty record."""
    text = host.podman.exec(container, ["cat", LEASE_PATH], check=False).stdout
    try:
        record = json.loads(text)
    except ValueError:
        return {}
    return record if isinstance(record, dict) else {}


def _object(host: Any, container: str, path: str = LOCK_PATH) -> Dict[str, Any]:
    return json.loads(
        host.podman.exec(container, ["python3", "-c", _OBJECT_SCRIPT, path]).stdout
    )


def _flock_free(host: Any, container: str) -> bool:
    """Whether the kernel lock on the canonical path is unheld inside the host."""
    result = host.podman.exec(
        container,
        ["bash", "-c",
         f"exec 9>>{LOCK_PATH} && if flock -n 9; then echo FREE; else echo HELD; fi"],
        check=False,
    )
    return result.stdout.strip() == "FREE"


def _validate_lease(host: Any, container: str, token: str) -> bool:
    """Ask the product's own validator whether a token still authorizes a mutation."""
    result = host.podman.exec(
        container,
        ["bash", "-c", _LEASE_VALIDATOR.format(lease=LEASE_PATH, lock=LOCK_PATH)],
        input_text=token + "\n",
        check=False,
    )
    return result.stdout.strip() == "VALID"


def _snapshot(host: Any, container: str) -> Dict[str, str]:
    """A digest per path a management command could rewrite, or ``"absent"``."""
    output = host.podman.exec(
        container, ["python3", "-c", _SNAPSHOT_SCRIPT, *_SNAPSHOT_PATHS],
        timeout=SSH_TIMEOUT_SECONDS,
    ).stdout
    return json.loads(output)


def _lock_files(host: Any, container: str) -> List[str]:
    """The lock-protocol files present on the host, so a stray one is visible."""
    output = host.podman.exec(
        container, ["python3", "-c", _LOCK_FILES_SCRIPT], timeout=SSH_TIMEOUT_SECONDS,
    ).stdout
    return json.loads(output)


def _current_channel(host: Any, container: str) -> Optional[str]:
    """The channel ``.env`` records, or ``None`` when the host is not installed."""
    result = host.podman.exec(
        container,
        ["bash", "-c",
         "test -f /opt/gowave/.env && "
         "sed -n 's/^GOWAVE_CHANNEL=//p' /opt/gowave/.env | head -n1"],
        check=False, timeout=SSH_TIMEOUT_SECONDS,
    )
    channel = result.stdout.strip()
    return channel if result.returncode == 0 and channel else None


def _run_cli(
    host: Any,
    container: str,
    argv: List[str],
    *,
    token_file: str = "",
    stdin_text: Optional[str] = None,
) -> Any:
    """Run ``gowave-auto.sh`` as an operator would, with no interactive input.

    A command with no stdin of its own would read the suite's stdin, so the
    redirection is explicit unless the caller is deliberately feeding the lease
    line. A lease is read from a file by the child's own shell, never spliced
    into an argument: authority in ``argv`` is authority in every process list.
    """
    parts = ["cd /repo &&"]
    if token_file:
        parts.append(f'GOWAVE_LEASE_TOKEN="$(cat {token_file})"')
    parts.append("exec bash ./gowave-auto.sh")
    parts.extend(shlex.quote(argument) for argument in argv)
    if stdin_text is None:
        parts.append("</dev/null")
    return host.podman.exec(
        container, ["bash", "-c", " ".join(parts)],
        input_text=stdin_text, check=False, timeout=CLI_TIMEOUT_SECONDS,
    )


def _combined(result: Any) -> str:
    return (result.stdout or "") + (result.stderr or "")


def _write_token(host: Any, container: str, token: str) -> str:
    """Stage a lease at mode 0600 inside the host and return its path."""
    host.podman.exec(
        container,
        ["bash", "-c", f"umask 077; cat > {NESTED_TOKEN_FILE}"],
        input_text=token + "\n", timeout=SSH_TIMEOUT_SECONDS,
    )
    return NESTED_TOKEN_FILE


def _entry_points(channel: Optional[str]) -> List[Dict[str, Any]]:
    """Every management entry point the spec names, with its own post-lock marker.

    The marker is the sentence the command prints *after* it took the lock and
    before it changed anything: it is what makes a refusal attributable to the
    lock rather than to a crash, a missing file, or a syntax error. ``channel``
    needs the host's own channel so that its marker is the idempotent no-op
    rather than a real switch; an uninstalled host gets the missing-``.env``
    sentence instead, which is likewise printed after the lock.
    """
    if channel:
        channel_argv = ["channel", channel]
        channel_marker = f"GoWave is already on channel '{channel}'."
    else:
        channel_argv = ["channel", "stable"]
        channel_marker = "Error: /opt/gowave/.env not found"
    return [
        {
            "label": "install",
            "argv": ["install", "invalid", "invalid", "ops@example.com"],
            "marker": "Invalid DNS hostname: invalid",
        },
        {"label": "node add", "argv": ["node", "add"], "marker": "Usage: gowave-auto.sh node add"},
        {
            "label": "node rollback",
            "argv": ["node", "rollback"],
            "marker": "Usage: gowave-auto.sh node rollback",
        },
        {
            "label": "node reapply",
            "argv": ["node", "reapply"],
            "marker": "Usage: gowave-auto.sh node reapply",
        },
        {
            "label": "domain-change",
            "argv": ["domain-change"],
            "marker": "Usage: gowave-auto.sh domain-change",
        },
        {"label": "channel", "argv": channel_argv, "marker": channel_marker},
        {
            "label": "uninstall",
            "argv": ["uninstall"],
            "marker": "WARNING: This will remove GoWave Auto NGINX managed components.",
        },
        {
            "label": "backup restore",
            "argv": ["restore", INVALID_ARCHIVE],
            "marker": "==> Initiating Restore from",
        },
    ]


def _write_shape(host: Any, container: str, shape: str) -> bool:
    """Put one of the refused objects at the canonical lock path.

    Returns whether the object is now there. A host that cannot express a shape —
    a transport without the privilege to hand a file to another user cannot —
    must not be handed the refusal it would have got: the shape is skipped and
    the evidence counts only what was exercised. On the real host every shape is
    written, so the count is the number of shapes the case names.
    """
    path = LOCK_PATH
    scripts = {
        "a symlink": f"rm -rf {path}; ln -sfn /tmp/gowave-lock-target {path}",
        "a directory": f"rm -rf {path}; mkdir -p {path}",
        "a FIFO": f"rm -rf {path}; mkfifo -m 0600 {path}",
        "a group-readable file": f"rm -rf {path}; : > {path}; chmod 0644 {path}",
        "a file owned by another user": (
            f"rm -rf {path}; : > {path}; chmod 0600 {path}; chown 65534:65534 {path}"
        ),
    }
    result = host.podman.exec(
        container, ["bash", "-c", scripts[shape]], check=False, timeout=SSH_TIMEOUT_SECONDS,
    )
    return result.returncode == 0


def _clear_shape(host: Any, container: str) -> None:
    host.podman.exec(
        container, ["bash", "-c", f"rm -rf {LOCK_PATH}"], timeout=SSH_TIMEOUT_SECONDS,
    )


def _move_aside(host: Any, container: str) -> str:
    """Move the lock directory aside, or say why this host cannot.

    An empty answer means the real directory is now ``/run/lock.case`` and the
    caller owns putting it back; anything else leaves the host untouched and is
    the sentence the evidence carries.
    """
    result = host.podman.exec(
        container,
        ["bash", "-c",
         f"test -d {LOCK_DIR} && test ! -L {LOCK_DIR} && "
         f"mv {LOCK_DIR} {LOCK_DIR}.case"],
        check=False, timeout=SSH_TIMEOUT_SECONDS,
    )
    if result.returncode == 0:
        return ""
    return result.stderr.strip() or "the directory could not be moved aside"


#: Whether the holder gets past its own `open` on the object. The probe repeats
#: that open exactly — the directory by descriptor, the name with `O_CREAT` and
#: `O_NOFOLLOW` — because the question is not what the file's mode says but which
#: check refuses it first. With `fs.protected_regular=2` and a sticky, world
#: writable `/run/lock`, the kernel refuses `O_CREAT` on a file another user owns
#: (measured: EACCES) one check before the mode and owner sentences, so the shape
#: would prove that a foreign object is refused rather than that ownership is what
#: refused it. The same directory under 0775 produces the owner sentence, which is
#: why the case measures instead of assuming either contour.
_OPEN_PROBE = (
    "import os, sys\n"
    "try:\n"
    "    dir_fd = os.open(os.path.dirname(sys.argv[1]),\n"
    "                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n"
    "    fd = os.open(os.path.basename(sys.argv[1]),\n"
    "                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)\n"
    "except OSError:\n"
    "    print('REFUSED')\n"
    "else:\n"
    "    os.close(fd)\n"
    "    print('OPENED')\n"
)


def ownership_shape_reachable(host: Any, container: str) -> bool:
    """Whether the ownership shape reaches the holder's ownership check here."""
    record = _object(host, container)
    if record.get("kind") != "regular":
        return False
    output = host.podman.exec(
        container, ["python3", "-c", _OPEN_PROBE, LOCK_PATH], check=False,
        timeout=SSH_TIMEOUT_SECONDS,
    ).stdout
    return output.strip() == "OPENED"


def case_pair_lock(product: Any) -> Dict[str, Any]:
    """LOCK-01: an occupied pair refuses a second runner, and existence is not ownership."""
    host = _topology(product)
    containers = _containers(host)
    with _pair(host) as (master, worker):
        owner = RemotePairLock(master, worker, run_id="podman-lock-owner")
        require(
            LOCK_CASE_ID,
            owner.acquire(),
            f"the first runner could not take the pair-wide lock: {owner.last_error}",
        )
        try:
            owner_tokens = dict(owner.lease_tokens)
            require(
                LOCK_CASE_ID,
                len(owner_tokens) == 2,
                f"the holder published {len(owner_tokens)} leases for a two-host pair",
            )
            published = {name: _lease(host, name) for name in containers}
            for name, address in zip(containers, _addresses(host)):
                require(
                    LOCK_CASE_ID,
                    published[name].get("run_id") == "podman-lock-owner",
                    f"{name} published the lease {published[name]!r}, which does not name "
                    "the run that holds it",
                )
                require(
                    LOCK_CASE_ID,
                    published[name].get("host") == address,
                    f"{name} published a lease for {published[name].get('host')!r} rather "
                    f"than its own address {address}",
                )
                require(
                    LOCK_CASE_ID,
                    published[name].get("lease_token") == owner_tokens[address],
                    f"{name} published a token the holder never printed: the lease a nested "
                    "command is handed is not the lease this host recorded",
                )

            # A second runner is a second process competing for the same inode. It
            # must fail before it modifies anything, and it must not keep the half
            # of the pair it managed to open.
            intruder = RemotePairLock(master, worker, run_id="podman-lock-intruder")
            taken = intruder.acquire()
            refusal = intruder.last_error
            require(
                LOCK_CASE_ID,
                not taken,
                "a second runner acquired the pair-wide lock while the first still held it, "
                "so two runs could mutate one host at the same time",
            )
            require(
                LOCK_CASE_ID,
                HELD_SENTENCE in refusal,
                f"the second runner was refused with {refusal!r}, which does not say that "
                "another process holds the lock",
            )
            require(
                LOCK_CASE_ID,
                intruder.lease_tokens == {},
                f"the refused runner kept the leases {sorted(intruder.lease_tokens)} of the "
                "hosts it was not allowed to touch",
            )
            unchanged = {name: _lease(host, name) for name in containers}
            require(
                LOCK_CASE_ID,
                unchanged == published,
                f"the refused runner rewrote the lease: {unchanged!r} instead of {published!r}",
            )
        finally:
            owner.release()

        # The lock file outlives its holder by design: it is created once and never
        # unlinked. A runner that read the path's existence as ownership would refuse
        # every later run, so the case proves the opposite — the file is still there,
        # and a fresh runner takes the pair and rewrites the stale lease.
        present = {name: _object(host, name) for name in containers}
        for name in containers:
            require(
                LOCK_CASE_ID,
                present[name].get("exists") is True,
                f"the released lock file is gone from {name}, so the case cannot tell "
                "existence from ownership",
            )
        stale = {name: _lease(host, name) for name in containers}
        third = RemotePairLock(master, worker, run_id="podman-lock-third")
        require(
            LOCK_CASE_ID,
            third.acquire(),
            f"a runner refused a pair whose previous holder had released it, reporting "
            f"{third.last_error}: the lock file's existence was read as ownership",
        )
        try:
            third_tokens = dict(third.lease_tokens)
            require(
                LOCK_CASE_ID,
                third_tokens != owner_tokens,
                "the new holder was handed the previous holder's tokens, so the lease is not "
                "bound to the holder that published it",
            )
            master_address = _addresses(host)[0]
            master_container = containers[0]
            require(
                LOCK_CASE_ID,
                not _validate_lease(host, master_container, stale[master_container]["lease_token"]),
                "the product's own validator still accepts the lease of a holder that released "
                "the lock, so a stale token is re-entrant authority",
            )
            require(
                LOCK_CASE_ID,
                _validate_lease(host, master_container, third_tokens[master_address]),
                "the product's own validator refuses the live holder's own lease, so no "
                "management command could run under a legitimate run",
            )
        finally:
            third.release()

    return {
        "owner_leases": len(owner_tokens),
        "owner_run_id": published[containers[0]].get("run_id"),
        "intruder_refusal": refusal,
        "intruder_leases": len(intruder.lease_tokens),
        "lease_after_refusal": unchanged == published,
        "lock_file_after_release": ",".join(
            f"{name}:{present[name].get('kind')}:{present[name].get('mode')}" for name in containers
        ),
        "stale_lease_rejected": True,
        "reacquired_leases": len(third_tokens),
        "live_lease_accepted": True,
    }


def case_lock_loss(product: Any) -> Dict[str, Any]:
    """LOCK-02: a lost lock-holder session stops mutating phases and forces reacquisition."""
    host = _topology(product)
    containers = _containers(host)
    with _pair(host) as (master, worker):
        pair = RemotePairLock(master, worker, run_id="podman-lock-loss")
        require(
            LOCK_LOSS_CASE_ID,
            pair.acquire(),
            f"the mutating run could not take the pair-wide lock: {pair.last_error}",
        )
        lost_tokens = dict(pair.lease_tokens)
        # The pair is taken in address order, so the holder this case terminates is
        # the first host of that order: that is what makes a partial acquisition
        # observable on the second one.
        first_address = min(_addresses(host))
        first_container = _container_for(host, first_address)
        lease = _lease(host, first_container)
        require(
            LOCK_LOSS_CASE_ID,
            isinstance(lease.get("holder_pid"), int),
            f"{first_container} published no holder pid, so the session could not be lost "
            "the way a dropped connection loses it",
        )
        # The loss is the host's own: the session's process is terminated inside the
        # container, exactly as a dropped SSH connection ends it, and the kernel
        # releases the flock the moment that process is gone.
        host.podman.exec(
            first_container, ["kill", "-TERM", str(lease["holder_pid"])], check=False,
        )
        stopped = wait_until(
            lambda: not pair.check_alive(),
            HOLDER_STOP_TIMEOUT_SECONDS,
            f"{LOCK_LOSS_CASE_ID}: the runner still reports both lock-holder sessions alive "
            f"after {first_container} terminated its own",
        )
        require(
            LOCK_LOSS_CASE_ID,
            stopped,
            f"the runner reports both lock-holder sessions alive after {first_container} "
            "terminated one: a lost session would go unnoticed and the next mutating phase "
            "would run with no exclusivity",
        )

        gate = pair_lock_gate(pair, "install")
        reading = pair_lock_gate(pair, "verify")
        require(
            LOCK_LOSS_CASE_ID,
            not gate.ok and gate.status == "INCOMPLETE",
            f"a mutating phase after the loss was gated {gate.status!r} rather than INCOMPLETE",
        )
        require(
            LOCK_LOSS_CASE_ID,
            "install" in gate.error and "lock was lost" in gate.error,
            f"the refusal reads {gate.error!r}, which neither names the phase it stopped nor "
            "says the lock was lost",
        )
        require(
            LOCK_LOSS_CASE_ID,
            reading.ok and reading.status == "",
            f"a read-only phase was gated {reading.status!r}: a run that lost its lock may "
            "still report what it sees",
        )
        require(
            LOCK_LOSS_CASE_ID,
            set(MUTATING_PHASES) == {"install", "traffic", "negative", "teardown"},
            f"the phases a lost lock stops are {sorted(MUTATING_PHASES)}, which is not the "
            "set of phases that change a host",
        )

        # Taking neither: a contender that wins the freed host must release it when
        # the other host refuses, or the pair would be half-held by a run that never
        # started.
        contender = RemotePairLock(master, worker, run_id="podman-lock-contender")
        require(
            LOCK_LOSS_CASE_ID,
            not contender.acquire(),
            "a contender acquired the pair after one of its holders was terminated, so the "
            "surviving host was never protected",
        )
        require(
            LOCK_LOSS_CASE_ID,
            HELD_SENTENCE in contender.last_error,
            f"the contender was refused with {contender.last_error!r}, which does not name "
            "the lock it could not take",
        )
        require(
            LOCK_LOSS_CASE_ID,
            _flock_free(host, first_container),
            f"the contender kept the lock on {first_container} after being refused on the "
            "other host, so a run that never started owns half the pair",
        )

        # Resuming is not a matter of trying again: both locks are reacquired and the
        # lost lease is dead, which is what makes the saved run state safe to reread.
        pair.release()
        resumed = RemotePairLock(master, worker, run_id="podman-lock-resumed")
        require(
            LOCK_LOSS_CASE_ID,
            resumed.acquire(),
            f"the pair could not be reacquired after the loss: {resumed.last_error}",
        )
        try:
            fresh_tokens = dict(resumed.lease_tokens)
            require(
                LOCK_LOSS_CASE_ID,
                fresh_tokens[first_address] != lost_tokens[first_address],
                "the reacquired lock reused the lost holder's token, so a stale lease would "
                "still authorize a mutation",
            )
            require(
                LOCK_LOSS_CASE_ID,
                not _validate_lease(host, first_container, lost_tokens[first_address]),
                "the product's own validator accepts the lease of the terminated holder",
            )
            require(
                LOCK_LOSS_CASE_ID,
                _validate_lease(host, first_container, fresh_tokens[first_address]),
                "the product's own validator refuses the reacquired holder's own lease",
            )
        finally:
            resumed.release()

    return {
        "terminated_holder": first_container,
        "session_loss_detected": stopped,
        "mutating_gate_status": gate.status,
        "mutating_gate_error": gate.error,
        "read_only_gate_ok": reading.ok,
        "contender_refusal": contender.last_error,
        "released_partial_acquisition": True,
        "reacquired_leases": len(fresh_tokens),
        "lost_lease_rejected": True,
        "live_lease_accepted": True,
    }


def case_lock_path(product: Any) -> Dict[str, Any]:
    """MLOCK-03: an unsafe lock path is refused, named, and left as it was found."""
    host = _topology(product)
    containers = _containers(host)
    refused: Dict[str, str] = {}
    untouched: Dict[str, bool] = {}
    skipped: List[str] = []
    with _pair(host) as (master, worker):
        shapes = (
            ("a symlink", f"the lock file {LOCK_PATH} is a symlink"),
            ("a directory", f"the lock file {LOCK_PATH} is a directory"),
            ("a FIFO", f"the lock file {LOCK_PATH} is not a regular file"),
            ("a group-readable file", f"the lock file {LOCK_PATH} grants group or other access"),
            ("a file owned by another user", f"the lock file {LOCK_PATH} is not owned by the runner"),
        )
        try:
            for shape, sentence in shapes:
                for container in containers:
                    # Both hosts start clean: otherwise the refusal this iteration
                    # reads could be the *other* host's leftover object, and the
                    # case would believe it proved this one.
                    for other in containers:
                        _clear_shape(host, other)
                    if not _write_shape(host, container, shape):
                        skipped.append(f"{shape} on {container}: the host could not write it")
                        continue
                    if (
                        shape == "a file owned by another user"
                        and not ownership_shape_reachable(host, container)
                    ):
                        skipped.append(
                            f"{shape} on {container}: the holder's own open refuses the "
                            "object, so it never reads the owner"
                        )
                        continue
                    before = _object(host, container)
                    attempt = RemotePairLock(master, worker, run_id="podman-lock-shape")
                    acquired = attempt.acquire()
                    attempt.release()
                    after = _object(host, container)
                    require(
                        LOCK_PATH_CASE_ID,
                        not acquired,
                        f"the pair-wide lock was taken while {LOCK_PATH} on {container} was "
                        f"{shape}",
                    )
                    expected_refusal = f"{_address_for(host, container)}: {sentence}"
                    require(
                        LOCK_PATH_CASE_ID,
                        attempt.last_error == expected_refusal,
                        f"{shape} on {container} was refused with {attempt.last_error!r} rather "
                        f"than {expected_refusal!r}: the refusal has to name that object on that "
                        "host, and a holder that died instead of refusing has refused nothing",
                    )
                    require(
                        LOCK_PATH_CASE_ID,
                        before == after,
                        f"{shape} on {container} was replaced or followed: {after!r} instead "
                        f"of {before!r}. A refusal may not repair a path by rewriting it",
                    )
                    refused[f"{shape} on {container}"] = attempt.last_error
                    untouched[f"{shape} on {container}"] = before == after
        finally:
            for container in containers:
                _clear_shape(host, container)

        # The parent directory is the same rule one level up: a lock directory that
        # is a link is refused rather than followed, and the host is left with the
        # real directory it started with.
        directory_refusals: List[str] = []
        for container in containers:
            reason = _move_aside(host, container)
            if reason:
                # `/run/lock` is a mount point on a systemd host, and a mount point
                # cannot be renamed: the shape is not one this host has, so it is
                # named rather than asserted against a sentence nothing can produce.
                skipped.append(f"a symlinked lock directory on {container}: {reason}")
                continue
            try:
                host.podman.exec(
                    container,
                    ["bash", "-c", f"ln -s {LOCK_DIR}.case {LOCK_DIR}"],
                    timeout=SSH_TIMEOUT_SECONDS,
                )
                attempt = RemotePairLock(master, worker, run_id="podman-lock-directory")
                acquired = attempt.acquire()
                attempt.release()
                directory_refusals.append(attempt.last_error)
                require(
                    LOCK_PATH_CASE_ID,
                    not acquired,
                    f"the pair-wide lock was taken while {LOCK_DIR} on {container} was a "
                    "symlink",
                )
                require(
                    LOCK_PATH_CASE_ID,
                    attempt.last_error
                    == f"{_address_for(host, container)}: the lock directory {LOCK_DIR} is a "
                    "symlink or not a directory",
                    f"a symlinked lock directory on {container} was refused with "
                    f"{attempt.last_error!r} rather than a sentence naming the directory",
                )
            finally:
                host.podman.exec(
                    container,
                    ["bash", "-c", f"rm -f {LOCK_DIR} && mv {LOCK_DIR}.case {LOCK_DIR}"],
                    timeout=SSH_TIMEOUT_SECONDS,
                )
            restored = _object(host, container, LOCK_DIR)
            require(
                LOCK_PATH_CASE_ID,
                restored.get("kind") == "directory",
                f"{LOCK_DIR} on {container} came back as {restored.get('kind')!r} after the "
                "case, so a refusal damaged the host it refused to lock",
            )

        # Every refusal above is about the object, not about a broken runner: with the
        # path restored, the same pair acquires both hosts.
        control = RemotePairLock(master, worker, run_id="podman-lock-control")
        require(
            LOCK_PATH_CASE_ID,
            control.acquire(),
            f"the pair-wide lock could not be taken on a clean path either: "
            f"{control.last_error}",
        )
        control.release()

    return {
        "shapes_refused": len(refused),
        "shape_sentences": json.dumps(refused, sort_keys=True),
        # A shape this contour cannot express counts as neither proved nor broken,
        # so it is listed by name: the evidence has to show what was left out and
        # why, rather than let a smaller `shapes_refused` read as a full sweep.
        "shapes_skipped": json.dumps(sorted(skipped)),
        "objects_untouched": all(untouched.values()),
        "directory_symlink_refusal": directory_refusals[0] if directory_refusals else "",
        "directory_restored": True,
        "control_acquired": True,
    }


def case_cli_entry_points(product: Any) -> Dict[str, Any]:
    """MLOCK-01: every management entry point refuses while a run owns the host.

    The lock is the runner's own — the same product holder the live runner uses —
    and the commands are the shipped ``gowave-auto.sh`` and
    ``assets/backup/gowave-backup.sh`` reading the same canonical path. A command
    that kept a private lock, or that did not lock at all, would print its own
    post-lock sentence here; the case asserts both that the sentence is absent and
    that the lock's own refusal is present, so a command that failed for any other
    reason cannot pass for a refusal.

    The Worker half of the requirement — ``remote_payload`` and
    ``remote_rollback`` — is not driven: a valid Worker lease would perform a full
    reinstall of the Worker, which is a mutation this case is forbidden to make.
    """
    host = _topology(product)
    master_container, worker_container = _containers(host)
    channel = _current_channel(host, master_container)
    host.podman.exec(
        master_container,
        ["bash", "-c",
         f"umask 022; printf 'not-a-gowave-archive' > {INVALID_ARCHIVE}"],
        timeout=SSH_TIMEOUT_SECONDS,
    )
    try:
        with _pair(host) as (master, worker):
            holder = RemotePairLock(master, worker, run_id="podman-lock-cli")
            require(
                CLI_CASE_ID,
                holder.acquire(),
                f"the run could not take the pair-wide lock the commands are refused "
                f"against: {holder.last_error}",
            )
            try:
                before = _snapshot(host, master_container)
                locks_before = _lock_files(host, master_container)
                refusals: Dict[str, str] = {}
                exit_codes: Dict[str, int] = {}
                reached: List[str] = []
                for entry in _entry_points(channel):
                    result = _run_cli(host, master_container, entry["argv"])
                    output = _combined(result)
                    if entry["marker"] in output:
                        reached.append(entry["label"])
                    require(
                        CLI_CASE_ID,
                        entry["marker"] not in output,
                        f"`{' '.join(entry['argv'])}` was not stopped by the lock that owns "
                        f"{master_container}: it printed {entry['marker']!r}. A command that "
                        "keeps a private lock, or does not take one, would mutate the host "
                        "underneath the runner",
                    )
                    require(
                        CLI_CASE_ID,
                        CLI_HELD_SENTENCE in output,
                        f"`{' '.join(entry['argv'])}` was stopped, but not by the mutation "
                        f"lock: it printed {output.strip()[-600:]!r} instead of "
                        f"{CLI_HELD_SENTENCE!r}",
                    )
                    require(
                        CLI_CASE_ID,
                        result.returncode != 0,
                        f"`{' '.join(entry['argv'])}` exited {result.returncode} after "
                        "refusing the lock, so a caller could read the refusal as success",
                    )
                    refusals[entry["label"]] = CLI_HELD_SENTENCE
                    exit_codes[entry["label"]] = result.returncode

                after = _snapshot(host, master_container)
                require(
                    CLI_CASE_ID,
                    after == before,
                    "a refused command changed the host: "
                    + json.dumps(
                        {path: [before.get(path), after.get(path)]
                         for path in sorted(set(before) | set(after))
                         if before.get(path) != after.get(path)},
                        sort_keys=True,
                    ),
                )
                locks_after = _lock_files(host, master_container)
                expected_locks = sorted([LOCK_PATH, LEASE_PATH])
                require(
                    CLI_CASE_ID,
                    locks_before == expected_locks,
                    f"the holder left {locks_before!r} in {LOCK_DIR} rather than the two "
                    "files the protocol names",
                )
                require(
                    CLI_CASE_ID,
                    locks_after == locks_before,
                    f"a refused command changed the lock protocol's own files: {locks_after!r} "
                    f"instead of {locks_before!r}",
                )
                require(
                    CLI_CASE_ID,
                    holder.check_alive(),
                    "a refused command ended the holder's own lock-holder session, so an "
                    "ordinary operator command could cancel a run in progress",
                )
            finally:
                holder.release()
    finally:
        host.podman.exec(
            master_container, ["bash", "-c", f"rm -f {INVALID_ARCHIVE}"], check=False,
            timeout=SSH_TIMEOUT_SECONDS,
        )

    # The Worker is the other half of the same protocol: the lease the holder
    # published there is the one its own commands would be handed, and the file
    # is the canonical one rather than a second, Worker-local name.
    with _pair(host) as (master, worker):
        worker_holder = RemotePairLock(master, worker, run_id="podman-lock-cli-worker")
        require(
            CLI_CASE_ID,
            worker_holder.acquire(),
            f"the Worker half of the pair could not be taken: {worker_holder.last_error}",
        )
        try:
            worker_lease = _lease(host, worker_container)
            require(
                CLI_CASE_ID,
                worker_lease.get("run_id") == "podman-lock-cli-worker",
                f"{worker_container} published {worker_lease!r}, which does not name the run "
                "that holds it",
            )
            require(
                CLI_CASE_ID,
                _object(host, worker_container).get("kind") == "regular",
                f"{worker_container} has no canonical lock file at {LOCK_PATH}, so its "
                "commands would take a lock the runner never touched",
            )
            worker_held = not _flock_free(host, worker_container)
            require(
                CLI_CASE_ID,
                worker_held,
                f"the canonical lock on {worker_container} is free while the runner holds the "
                "pair, so a Worker command would not be refused",
            )
        finally:
            worker_holder.release()

    return {
        "entry_points": len(refusals),
        "refusals": json.dumps(refusals, sort_keys=True),
        "exit_codes": json.dumps(exit_codes, sort_keys=True),
        "post_lock_markers_absent": not reached,
        "channel_target": channel or "",
        "host_unchanged": after == before,
        "lock_files": ",".join(Path(path).name for path in expected_locks),
        "lock_files_unchanged": locks_after == locks_before,
        "holder_session_survived": True,
        "worker_lock_held": worker_held,
    }


def case_nested_lease(product: Any) -> Dict[str, Any]:
    """MLOCK-02: a nested command runs on the run's own lease, and on nothing else.

    The child is ``domain-change`` with no arguments: it takes the lock first and
    then prints its usage, so acceptance is observable as that usage sentence and a
    refusal is observable as the lock's own sentence, with no mutation on either
    path. Acceptance is proved three ways beyond the sentence — the parent's holder
    session is still alive afterwards, the lease file is byte-identical, and the
    host's digests are unchanged — because "the child ran" would otherwise be
    "the child took the lock the parent had already dropped".
    """
    host = _topology(product)
    master_container, _ = _containers(host)
    address = _address_for(host, master_container)
    child = ["domain-change"]
    marker = "Usage: gowave-auto.sh domain-change <panel-domain> <reality-domain>"

    def drive(**arguments: Any) -> Tuple[Any, str]:
        result = _run_cli(host, master_container, child, **arguments)
        return result, _combined(result)

    accepted_env = accepted_stdin = False
    lease_unchanged = host_unchanged = False
    holder_survived = False
    bare_output = stale_output = replayed_output = ""
    lost_rejected = False
    try:
        with _pair(host) as (master, worker):
            holder = RemotePairLock(master, worker, run_id="podman-lock-nested")
            require(
                NESTED_CASE_ID,
                holder.acquire(),
                f"the run could not take the pair-wide lock its child is meant to reuse: "
                f"{holder.last_error}",
            )
            try:
                live_token = holder.lease_tokens[address]
                before = _snapshot(host, master_container)
                lease_before = host.podman.exec(
                    master_container, ["cat", LEASE_PATH], timeout=SSH_TIMEOUT_SECONDS,
                ).stdout

                # 1. An operator with no lease at all: the lock refuses, so the
                #    acceptance below is about the lease and not about the lock
                #    being free.
                _, bare_output = drive()
                require(
                    NESTED_CASE_ID,
                    marker not in bare_output and CLI_HELD_SENTENCE in bare_output,
                    f"a child with no lease was not refused by the lock: {bare_output.strip()!r}",
                )

                # 2. The run's own lease in the environment.
                token_file = _write_token(host, master_container, live_token)
                _, env_output = drive(token_file=token_file)
                require(
                    NESTED_CASE_ID,
                    marker in env_output and CLI_HELD_SENTENCE not in env_output,
                    f"the run's own lease was refused in the environment: "
                    f"{env_output.strip()[-600:]!r}. A nested deployment could never run",
                )
                require(
                    NESTED_CASE_ID,
                    CLI_STALE_SENTENCE not in env_output,
                    f"the run's own live lease was reported stale: {env_output.strip()!r}",
                )
                accepted_env = True

                # 3. The same lease as the stdin line an SSH pipeline carries.
                _, stdin_output = drive(
                    stdin_text=f"GOWAVE_LEASE: {live_token}\n"
                )
                require(
                    NESTED_CASE_ID,
                    marker in stdin_output and CLI_HELD_SENTENCE not in stdin_output,
                    f"the run's own lease was refused on stdin, so a child reached over an "
                    f"SSH pipeline cannot run: {stdin_output.strip()[-600:]!r}",
                )
                accepted_stdin = True

                lease_after = host.podman.exec(
                    master_container, ["cat", LEASE_PATH], timeout=SSH_TIMEOUT_SECONDS,
                ).stdout
                require(
                    NESTED_CASE_ID,
                    lease_after == lease_before,
                    f"an accepted child rewrote the lease: {lease_after.strip()!r} instead of "
                    f"{lease_before.strip()!r}. The parent's authority is not the child's to "
                    "re-publish",
                )
                lease_unchanged = True
                after = _snapshot(host, master_container)
                require(
                    NESTED_CASE_ID,
                    after == before,
                    "an accepted child changed the host although it only printed its usage",
                )
                host_unchanged = True
                require(
                    NESTED_CASE_ID,
                    holder.check_alive(),
                    "an accepted child ended the parent's lock-holder session, so it released "
                    "the exclusivity it was granted",
                )
                holder_survived = True
                require(
                    NESTED_CASE_ID,
                    not _flock_free(host, master_container),
                    "the lock is free after the child ran: the child's own descriptor took "
                    "over instead of the parent keeping exclusivity",
                )
            finally:
                holder.release()

            # 4. A lease from a holder that has released: the host is owned by some
            #    other run, so the token is presented while the lock is genuinely
            #    occupied and the refusal is about the token, not about a free host.
            stale_token = live_token
            successor = RemotePairLock(master, worker, run_id="podman-lock-nested-next")
            require(
                NESTED_CASE_ID,
                successor.acquire(),
                f"the pair could not be taken by a second holder: {successor.last_error}",
            )
            try:
                stale_run, stale_output = drive(
                    stdin_text=f"GOWAVE_LEASE: {stale_token}\n"
                )
                require(
                    NESTED_CASE_ID,
                    marker not in stale_output,
                    f"a lease from a released holder was accepted: the child printed "
                    f"{marker!r} although its authority had ended",
                )
                require(
                    NESTED_CASE_ID,
                    CLI_STALE_SENTENCE in stale_output,
                    f"a lease from a released holder was refused with "
                    f"{stale_output.strip()[-600:]!r} rather than {CLI_STALE_SENTENCE!r}",
                )
                require(
                    NESTED_CASE_ID,
                    stale_run.returncode != 0,
                    "a command handed a stale lease exited 0, so a pipeline would read the "
                    "refusal as a completed mutation",
                )
            finally:
                successor.release()

            # 5. A lease whose holder died: authority is the live session, not the
            #    bytes on disk, so the token is rejected by the product's own
            #    validator and by a command once another holder owns the host.
            replay = RemotePairLock(master, worker, run_id="podman-lock-nested-replay")
            require(
                NESTED_CASE_ID,
                replay.acquire(),
                f"the pair could not be taken for the loss half: {replay.last_error}",
            )
            replayed_token = replay.lease_tokens[address]
            lease = _lease(host, master_container)
            require(
                NESTED_CASE_ID,
                isinstance(lease.get("holder_pid"), int),
                f"{master_container} published no holder pid, so its session could not be lost",
            )
            host.podman.exec(
                master_container, ["kill", "-TERM", str(lease["holder_pid"])], check=False,
            )
            stopped = wait_until(
                lambda: not replay.check_alive(),
                HOLDER_STOP_TIMEOUT_SECONDS,
                f"{NESTED_CASE_ID}: the runner still reports both holder sessions alive after "
                f"{master_container} terminated its own",
            )
            require(
                NESTED_CASE_ID,
                stopped,
                "the runner did not notice its own holder session ending, so a replayed lease "
                "would be tried against a lock nobody holds",
            )
            require(
                NESTED_CASE_ID,
                not _validate_lease(host, master_container, replayed_token),
                "the product's own validator still accepts the lease of a terminated holder",
            )
            lost_rejected = True
            replay.release()

            successor = RemotePairLock(master, worker, run_id="podman-lock-nested-after")
            require(
                NESTED_CASE_ID,
                successor.acquire(),
                f"the pair could not be reacquired after the loss: {successor.last_error}",
            )
            try:
                replayed_run, replayed_output = drive(
                    stdin_text=f"GOWAVE_LEASE: {replayed_token}\n"
                )
                require(
                    NESTED_CASE_ID,
                    marker not in replayed_output,
                    "a lease replayed from a terminated holder was accepted by a command",
                )
                require(
                    NESTED_CASE_ID,
                    CLI_STALE_SENTENCE in replayed_output,
                    f"a replayed lease was refused with {replayed_output.strip()[-600:]!r} "
                    f"rather than {CLI_STALE_SENTENCE!r}",
                )
                require(
                    NESTED_CASE_ID,
                    replayed_run.returncode != 0,
                    "a command handed a replayed lease exited 0",
                )
            finally:
                successor.release()
    finally:
        host.podman.exec(
            master_container, ["bash", "-c", f"rm -f {NESTED_TOKEN_FILE}"], check=False,
            timeout=SSH_TIMEOUT_SECONDS,
        )

    return {
        "child_command": " ".join(child),
        "bare_refusal": CLI_HELD_SENTENCE if CLI_HELD_SENTENCE in bare_output else "",
        "env_lease_accepted": accepted_env,
        "stdin_lease_accepted": accepted_stdin,
        "accepted_marker": marker,
        "lease_unchanged": lease_unchanged,
        "host_unchanged": host_unchanged,
        "holder_session_survived": holder_survived,
        "stale_lease_refusal": CLI_STALE_SENTENCE if CLI_STALE_SENTENCE in stale_output else "",
        "lost_lease_rejected": lost_rejected,
        "replayed_lease_refusal": (
            CLI_STALE_SENTENCE if CLI_STALE_SENTENCE in replayed_output else ""
        ),
    }
