#!/usr/bin/env python3
"""Capture and restore the firewall state a transaction is about to change.

`capture` records what UFW read before the first mutation - the enabled state,
the default policies, the persisted configuration files and the live rulesets -
and `restore` puts exactly that back. Both refuse to act on a state they cannot
read back, so a host never ends up with a firewall this installer cannot undo.

The streamed Worker payload carries the same two actions as a heredoc, because
a remote host has no repository to read them from. `tests/test_firewall.py`
runs both copies against one fake host and refuses the tree when they disagree.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

root, image, action = sys.argv[1:4]

CONFIG_FILES = (
    "/etc/default/ufw",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/ufw/before.rules",
    "/etc/ufw/before6.rules",
    "/etc/ufw/after.rules",
    "/etc/ufw/after6.rules",
)
MANIFEST = os.path.join(image, "manifest.json")


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def run(argv, stdin_text=None):
    result = subprocess.run(argv, capture_output=True, text=True, input=stdin_text)
    return result.returncode, result.stdout, result.stderr


def digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def digest_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def normalized(text):
    """The ruleset without the bookkeeping `iptables-save` adds on its own.

    Every dump is stamped with the moment it ran and carries the live
    counters of each chain, and `iptables-restore` zeroes those counters.
    Neither is a rule, so a read-back compares what is left.
    """
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(":") and line.endswith("]"):
            line = line[: line.rindex("[")] + "[0:0]"
        lines.append(line)
    return "\n".join(lines)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".firewall-image.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def capture():
    if os.path.lexists(image):
        fail("Firewall before-image " + image + " already exists; refusing to overwrite the state it holds.")
    status_code, status_text, status_error = run(["ufw", "status", "verbose"])
    if status_code != 0:
        fail(
            "ufw status verbose exited " + str(status_code) + "; refusing to change a firewall this install cannot "
            "restore: " + status_error.strip()[-300:]
        )
    first = status_text.splitlines()[0].strip() if status_text.strip() else ""
    if first not in ("Status: active", "Status: inactive"):
        fail("ufw status verbose printed no status line; refusing to change a firewall this install cannot restore.")
    defaults = {}
    for line in status_text.splitlines():
        if not line.startswith("Default:"):
            continue
        for part in line[len("Default:"):].split(","):
            words = part.split()
            if len(words) >= 2:
                defaults[words[1].strip("()")] = words[0]
    # `ufw status verbose` prints no Default line until the firewall has been
    # enabled once: an inactive firewall holds no policy, so there is none to
    # restore and the image records that instead of refusing the install.
    if first == "Status: active" and set(defaults) != {"incoming", "outgoing", "routed"}:
        fail(
            "ufw status verbose printed no complete default policy line; refusing to change a firewall this "
            "install cannot restore."
        )
    dumps = {}
    for name, argv in (("iptables", ["iptables-save"]), ("ip6tables", ["ip6tables-save"])):
        code, text, error = run(argv)
        if code != 0:
            if name == "ip6tables" and not os.path.exists(under("/proc/net/if_inet6")):
                dumps[name] = None
                continue
            fail(
                argv[0] + " exited " + str(code) + "; refusing to change a firewall this install cannot restore: "
                + error.strip()[-300:]
            )
        dumps[name] = text
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {
        "created_by_tx": True,
        "enabled": first == "Status: active",
        "status_verbose": status_text,
        "defaults": defaults,
        "files": {},
        "iptables": None,
        "ip6tables": None,
    }
    try:
        for path in CONFIG_FILES:
            real = under(path)
            if not os.path.lexists(real):
                continue
            if os.path.islink(real) or not os.path.isfile(real):
                fail(
                    "UFW configuration " + real + " is not a regular file; refusing to change a firewall this "
                    "install cannot restore."
                )
            with open(real, "rb") as stream:
                payload = stream.read()
            copy = "file-" + digest_bytes(path.encode("utf-8"))[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(real)
            data["files"][path] = {
                "copy": copy,
                "sha256": digest_bytes(payload),
                "mode": state.st_mode & 0o7777,
                "uid": state.st_uid,
                "gid": state.st_gid,
            }
        for name, text in dumps.items():
            if text is None:
                continue
            copy = name + "-save.txt"
            write_atomic(os.path.join(image, copy), text.encode("utf-8"), 0o600)
            data[name] = {"copy": copy, "sha256": digest_bytes(text.encode("utf-8"))}
        write_atomic(MANIFEST, (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8"), 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def restore():
    if os.path.islink(MANIFEST):
        fail("Firewall before-image " + MANIFEST + " is a symlink; refusing to restore from it.")
    if not os.path.isfile(MANIFEST):
        fail("No firewall before-image at " + image + "; refusing to guess which rules this install added.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail("Firewall before-image " + MANIFEST + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Firewall before-image " + MANIFEST + " does not claim this product created it.")
    for key in ("enabled", "status_verbose", "defaults", "files", "iptables"):
        if key not in data:
            fail("Firewall before-image " + MANIFEST + " is incomplete: no " + key + ".")
    if not isinstance(data["files"], dict) or not isinstance(data["iptables"], dict):
        fail("Firewall before-image " + MANIFEST + " names no restorable files.")
    for path, meta in data["files"].items():
        copy = os.path.join(image, str(meta.get("copy") or ""))
        if not os.path.isfile(copy) or os.path.islink(copy):
            fail("Firewall before-image copy for " + path + " is missing.")
        if digest_file(copy) != meta.get("sha256"):
            fail("Firewall before-image copy for " + path + " changed after it was written.")
        with open(copy, "rb") as stream:
            payload = stream.read()
        target = under(path)
        write_atomic(target, payload, int(meta.get("mode") or 0o644))
        try:
            os.chown(target, int(meta.get("uid") or 0), int(meta.get("gid") or 0))
        except OSError:
            pass
    # The enabled state first: `ufw --force disable` flushes the chains, so a
    # dump applied before it would be the rules this install added, not these.
    state = "enable" if data["enabled"] else "disable"
    code, _, error = run(["ufw", "--force", state])
    if code != 0:
        fail("ufw --force " + state + " exited " + str(code) + ": " + error.strip()[-300:])
    restored = {}
    for name, argv in (("iptables", ["iptables-restore"]), ("ip6tables", ["ip6tables-restore"])):
        entry = data.get(name)
        if not isinstance(entry, dict):
            continue
        copy = os.path.join(image, str(entry.get("copy") or ""))
        if not os.path.isfile(copy):
            fail("Firewall before-image copy for " + name + " is missing.")
        with open(copy, "r", encoding="utf-8") as stream:
            text = stream.read()
        code, _, error = run(argv, stdin_text=text)
        if code != 0:
            fail(argv[0] + " exited " + str(code) + ": " + error.strip()[-300:])
        restored[name] = text
    code, status_text, _ = run(["ufw", "status", "verbose"])
    if code != 0 or status_text != data["status_verbose"]:
        fail("The restored firewall does not read back as the before-image.")
    code, saved, _ = run(["iptables-save"])
    if code != 0 or normalized(saved) != normalized(restored.get("iptables", "")):
        fail("The restored IPv4 ruleset does not match the before-image.")
    # A dual-stack host filters on two tables, and a restored v4 ruleset proves
    # nothing about the v6 one the previous run opened.
    if "ip6tables" in restored:
        code, saved, _ = run(["ip6tables-save"])
        if code != 0 or normalized(saved) != normalized(restored["ip6tables"]):
            fail("The restored IPv6 ruleset does not match the before-image.")


if action == "capture":
    capture()
else:
    restore()
