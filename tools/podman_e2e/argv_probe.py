"""Master-side argv observer for the Worker deployment, reproduced in a container.

The live runner traces the Master host around its own ``gowave-auto.sh node add``
and parses that trace on the same host, so the ``envp`` vector strace prints
with ``-v`` never leaves it. This module is the container's copy of the same
observer: ``strace`` is installed in the Master container, the trace is taken
there around the operator's real dispatch, and the scanner runs there too —
only counts come back over ``podman exec``.

The file is therefore stdlib-only and self-contained: it is delivered into the
container and executed as a script there.

    python3 argv_probe.py fixtures             # acceptance fixtures, prints JSON
    python3 argv_probe.py scan <trace>         # scans argv, SECRET_KEY on stdin
    python3 argv_probe.py exec-execveat <arg>  # a helper leg used by the fixtures

What the observer states, and what it does not: it sees the local process tree
of the dispatch (the shell, the SSH client and everything they execute), with
both ``execve`` and ``execveat``. Remote Worker processes are beyond the SSH
boundary and are not observed. ``envp`` is parsed only to be discarded: it is
never returned, recorded or logged.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# The observer's -s limit: 32 pages, the number the live runner computes on the
# Master so that a long argv string is captured whole rather than cut at the
# 32-byte default.
LIMIT_FACTOR = 32
TRUNCATED_LIMIT = 32
TRACE_DIR = "/run/gowave_e2e_strace"
TRACE_PATH = TRACE_DIR + "/node_add.trace"
PROBE_PATH = TRACE_DIR + "/argv_probe.py"
EXEC_SYSCALLS = ("execve", "execveat")

SENTINEL_AFTER_32 = "SENTINEL_AFTER_BYTE_32_" + "X" * 60
SENTINEL_FINAL = "SENTINEL_IN_FINAL_ELEMENT_128"
MANY_ELEMENTS = 128
MANY_ARGUMENTS: Tuple[str, ...] = tuple(f"arg{index}" for index in range(MANY_ELEMENTS - 1)) + (SENTINEL_FINAL,)

FIXTURE_TIMEOUT_SECONDS = 600
SCAN_TIMEOUT_SECONDS = 600
SECRET_TIMEOUT_SECONDS = 120
INSTALL_TIMEOUT_SECONDS = 600

RECORD_RE = re.compile(r"(?<![\w.])(execve|execveat)\(")
PID_RE = re.compile(r"^\s*(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)")
UNFINISHED = "<unfinished ...>"
RESUMED_RE = re.compile(r"<\.\.\.\s+\w+\s+resumed>")

_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f",
    "a": "\a", "b": "\b", '"': '"', "'": "'", "\\": "\\",
}


# --------------------------------------------------------------- the numbers
def page_size() -> int:
    return int(os.sysconf("SC_PAGE_SIZE"))


def trace_limit(size: Optional[int] = None) -> int:
    """The ``-s`` limit the observer uses, in bytes."""
    return LIMIT_FACTOR * (size if size is not None else page_size())


# ------------------------------------------------------------ what to run it
def strace_prefix(trace_path: str, limit: int) -> str:
    return (
        "strace -f -v "
        f"-s {int(limit)} "
        "-e trace=execve,execveat "
        f"-o {shlex.quote(trace_path)} "
    )


def install_strace_script() -> str:
    """The live runner's own recipe: install strace only when it is absent."""
    return (
        "command -v strace >/dev/null 2>&1 || "
        "(apt-get update -qq && apt-get install -y --no-install-recommends strace)"
    )


def flags_script() -> str:
    return "strace -f -v -s 100 -e trace=execve,execveat true"


def limit_script() -> str:
    return 'python3 -c \'import os; print(32 * os.sysconf("SC_PAGE_SIZE"))\''


def probe_directory_script() -> str:
    """Create the private trace directory, and touch nothing in it.

    Delivery must not clear the trace: the case places the probe after the
    deployment has already written it, so a preparation that also dropped "an
    earlier trace" would delete the file the case reads and report the dispatch
    as never observed. Dropping a stale trace belongs to the dispatch itself,
    which is ``trace_reset_script()``.
    """
    return f"mkdir -p -m 0700 {shlex.quote(TRACE_DIR)}"


def trace_reset_script() -> str:
    """Prepare the directory and drop the trace of an earlier dispatch."""
    return f"{probe_directory_script()} && rm -f {shlex.quote(TRACE_PATH)}"


def client_script() -> str:
    """The name of the client the deployment dispatches through, on this host.

    The observer counts the remote dispatch by that name instead of assuming a
    spelling: ``node add`` runs whatever client the Master resolves, and a probe
    that hard-coded the name would report zero execs on a host that renamed it —
    which reads as "the trace missed the deployment" when the trace was fine.
    """
    return 'basename "$(command -v ssh)"'


# ------------------------------------------------------------------ parsing
def unescape(text: str) -> str:
    """Decode the escapes strace puts in a quoted argument.

    strace prints every byte it cannot show literally as an octal escape, so a
    secret containing a quote, a backslash or a non-ASCII byte reaches this
    function escaped. Decoding it is what makes the scan a scan of argv bytes
    rather than of strace's rendering of them.
    """
    raw = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            raw += char.encode("utf-8", "surrogateescape")
            index += 1
            continue
        triplet = text[index + 1:index + 4]
        if len(triplet) == 3 and triplet.isdigit():
            raw.append(int(triplet, 8) & 0xFF)
            index += 4
            continue
        escaped = text[index + 1:index + 2]
        if escaped in _ESCAPES:
            raw += _ESCAPES[escaped].encode("utf-8")
            index += 2
            continue
        raw += escaped.encode("utf-8", "surrogateescape")
        index += 2
    return raw.decode("utf-8", "replace")


def _first_array(arguments: str) -> Tuple[str, int]:
    """The first bracketed array of an exec record — argv; envp comes after it."""
    start = arguments.find("[")
    if start < 0:
        return "", -1
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(arguments)):
        char = arguments[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return arguments[start:index + 1], index + 1
    return arguments[start:], len(arguments)


def array_elements(raw: str) -> Tuple[List[str], Dict[str, bool]]:
    """Decode the string elements of one strace array and its omission markers.

    strace marks a string it cut at the ``-s`` limit by closing the quote and
    appending ``...``, and marks an array it cut short with a bare ``...``
    element. Both mean the observation is incomplete, so both are reported.
    """
    elements: List[str] = []
    flags = {"truncated": False, "abbreviated": False}
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == '"':
            cursor = index + 1
            literal: List[str] = []
            while cursor < len(raw):
                current = raw[cursor]
                if current == "\\":
                    octal = raw[cursor + 1:cursor + 4]
                    if len(octal) == 3 and octal.isdigit():
                        literal.append(raw[cursor:cursor + 4])
                        cursor += 4
                    else:
                        literal.append(raw[cursor:cursor + 2])
                        cursor += 2
                    continue
                if current == '"':
                    break
                literal.append(current)
                cursor += 1
            elements.append(unescape("".join(literal)))
            index = cursor + 1
            if raw.startswith("...", index):
                flags["truncated"] = True
                index += 3
            continue
        if char == "." and raw.startswith("...", index):
            flags["abbreviated"] = True
            index += 3
            continue
        index += 1
    return elements, flags


def _record(syscall: str, arguments: str) -> Dict[str, Any]:
    array, _end = _first_array(arguments)
    elements, flags = array_elements(array)
    return {
        "syscall": syscall,
        "argv": elements,
        "truncated": flags["truncated"],
        "abbreviated": flags["abbreviated"],
    }


def parse_records(text: str) -> Dict[str, Any]:
    """Every completed exec record in a ``-f`` trace, with envp left behind.

    ``-f`` interleaves the records of concurrent processes, so one record can
    arrive as an ``<unfinished ...>`` line plus a ``<... execve resumed>`` line.
    Those two halves are rejoined here: dropping either half would silently lose
    an exec, and losing one is exactly the failure this observer exists to
    refuse. A record still unfinished at the end of the file is reported,
    because a truncated trace proves nothing.
    """
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    pending: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        pid_match = PID_RE.match(line)
        pid = (pid_match.group(1) or pid_match.group(2)) if pid_match else ""
        label = pid or ""
        if UNFINISHED in line:
            pending[label] = line.split(UNFINISHED, 1)[0]
            continue
        resumed_match = RESUMED_RE.search(line)
        if resumed_match:
            head = pending.pop(label, None)
            if head is None:
                errors.append("a resumed exec record names a process with no unfinished record")
                continue
            record_line = head.rstrip() + line[resumed_match.end():]
            match = RECORD_RE.search(record_line)
            if not match:
                errors.append("a resumed exec record holds no exec call")
                continue
            records.append(_record(match.group(1), record_line[match.end():]))
            continue
        match = RECORD_RE.search(line)
        if not match:
            continue
        arguments = line[match.end():]
        if not _first_array(arguments)[0]:
            if "= -1" in line:
                # A refused exec never ran, so it carries no argv to inspect.
                continue
            errors.append("an exec record holds no argv vector")
            continue
        records.append(_record(match.group(1), arguments))
    if pending:
        errors.append(f"the trace ends inside {len(pending)} exec record(s)")
    return {"records": records, "errors": errors}


def secret_forms(secret: str) -> List[str]:
    """The raw secret plus the encodings an argv could carry it in."""
    if not secret:
        return []
    forms = [secret]
    encoded = secret.encode("utf-8", "surrogateescape")
    if len(encoded) >= 16:
        standard = base64.b64encode(encoded).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(encoded).decode("ascii")
        forms.extend((standard, standard.rstrip("="), urlsafe, urlsafe.rstrip("=")))
    return [form for form in forms if form]


def scan_trace_text(text: str, secrets: Sequence[str], client: str = "") -> Dict[str, Any]:
    """Judge one trace: is every argv complete, and does any of them hold the secret?"""
    parsed = parse_records(text)
    records: List[Dict[str, Any]] = parsed["records"]
    errors: List[str] = list(parsed["errors"])
    forms = [form for secret in secrets for form in secret_forms(secret)]
    secret_found = any(
        form in element
        for record in records
        for element in record["argv"]
        for form in forms
    )
    counts = {name: sum(1 for record in records if record["syscall"] == name) for name in EXEC_SYSCALLS}
    client_execs = sum(
        1 for record in records
        if client and record["argv"] and os.path.basename(record["argv"][0]) == client
    )
    if not secrets:
        errors.append("no SECRET_KEY was supplied, so its absence cannot be observed")
    if not client:
        errors.append("the client the deployment dispatches through is not known, so the "
                      "remote dispatch cannot be looked for in the trace")
    truncated = any(record["truncated"] for record in records)
    abbreviated = any(record["abbreviated"] for record in records)
    if secret_found:
        status = "FAIL"
    elif truncated or abbreviated or errors or not records:
        status = "INCOMPLETE"
    else:
        status = "PASS"
    return {
        "status": status,
        "exec_count": len(records),
        "execve_count": counts["execve"],
        "execveat_count": counts["execveat"],
        "ssh_execs": client_execs,
        "secret_found": secret_found,
        "truncated": truncated,
        "abbreviated": abbreviated,
        "errors": errors,
    }


def scan_trace_file(path: str, secrets: Sequence[str], client: str = "") -> Dict[str, Any]:
    """Scan the trace where it was taken and remove it, envp included."""
    if not os.path.exists(path):
        facts = scan_trace_text("", secrets, client)
        facts["status"] = "INCOMPLETE"
        facts["errors"].append("the trace file is absent, so nothing was observed")
        facts.update({"trace_bytes": 0, "trace_removed": False})
        return facts
    size = os.path.getsize(path)
    with open(path, "r", errors="replace") as handle:
        text = handle.read()
    facts = scan_trace_text(text, secrets, client)
    facts["trace_bytes"] = size
    facts["trace_removed"] = _remove(path)
    return facts


def _remove(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False


# ----------------------------------------------------------------- fixtures
FIXTURE_SPECS: Tuple[Dict[str, Any], ...] = (
    {
        "name": "long-argument-execve",
        "syscall": "execve",
        "arguments": (SENTINEL_AFTER_32,),
        "limit": None,
        "expect_sentinel": True,
    },
    {
        "name": "long-argument-execveat",
        "syscall": "execveat",
        "arguments": (SENTINEL_AFTER_32,),
        "limit": None,
        "expect_sentinel": True,
    },
    {
        "name": "long-argument-limit-control",
        "syscall": "execve",
        "arguments": (SENTINEL_AFTER_32,),
        "limit": TRUNCATED_LIMIT,
        "expect_sentinel": False,
    },
    {
        "name": "many-arguments-execve",
        "syscall": "execve",
        "arguments": MANY_ARGUMENTS,
        "limit": None,
        "expect_sentinel": True,
    },
)


def _judge_fixture(spec: Dict[str, Any], text: str) -> Dict[str, Any]:
    records = parse_records(text)["records"]
    matching = [record for record in records if record["syscall"] == spec["syscall"]]
    sentinel = SENTINEL_FINAL if spec["name"].startswith("many") else SENTINEL_AFTER_32
    carrying = [record for record in matching if any(element == sentinel for element in record["argv"])]
    facts: Dict[str, Any] = {
        "name": spec["name"],
        "syscall": spec["syscall"],
        "records": len(matching),
        "sentinel": bool(carrying),
        "truncated": any(record["truncated"] for record in matching),
        "abbreviated": any(record["abbreviated"] for record in matching),
    }
    if spec["expect_sentinel"]:
        if not carrying:
            facts["status"] = "FAIL"
            facts["reason"] = (
                f"no {spec['syscall']} record carries the complete {sentinel} sentinel"
                if matching else f"the trace holds no {spec['syscall']} record"
            )
            return facts
        record = carrying[0]
        facts["elements"] = len(record["argv"])
        if record["truncated"] or record["abbreviated"]:
            facts["status"] = "FAIL"
            facts["reason"] = "the record carrying the sentinel carries an omission marker"
            return facts
        if spec["name"] == "many-arguments-execve":
            expected = list(MANY_ARGUMENTS)
            tail = record["argv"][-len(expected):]
            if tail != expected:
                facts["status"] = "FAIL"
                facts["reason"] = (
                    f"the final {len(expected)} argv elements are not arg0..arg{MANY_ELEMENTS - 2} "
                    "followed by the sentinel, in that order"
                )
                return facts
            if len(record["argv"]) < MANY_ELEMENTS:
                facts["status"] = "FAIL"
                facts["reason"] = f"the record holds {len(record['argv'])} argv elements, fewer than {MANY_ELEMENTS}"
                return facts
        facts["status"] = "PASS"
        return facts
    # The control leg: the same argument under the 32-byte default limit must be
    # cut, and the cut must be visible as a truncation marker. Proving both is
    # what says the limit matters and that the judge can see a cut at all.
    facts["status"] = "PASS"
    if carrying:
        facts["status"] = "FAIL"
        facts["reason"] = "the sentinel survived a 32-byte limit, so a cut is not observable here"
    elif not facts["truncated"]:
        facts["status"] = "FAIL"
        facts["reason"] = "the sentinel is absent but no truncation marker was reported"
    return facts


def judge_fixtures(limit: int, traces: Dict[str, str]) -> Dict[str, Any]:
    """Judge the acceptance legs from their recorded traces."""
    reported: List[Dict[str, Any]] = []
    errors: List[str] = []
    for spec in FIXTURE_SPECS:
        text = traces.get(spec["name"], "")
        facts = _judge_fixture(spec, text)
        facts["limit"] = spec["limit"] or limit
        reported.append(facts)
        if facts["status"] != "PASS":
            errors.append(f"{spec['name']}: {facts.get('reason', 'the leg failed')}")
    return {
        "status": "FAIL" if errors else "PASS",
        "page_size": page_size(),
        "limit": limit,
        "fixtures": reported,
        "errors": errors,
    }


def acceptance_fixtures(workdir: str = TRACE_DIR, limit: Optional[int] = None) -> Dict[str, Any]:
    """Run each acceptance leg under strace and judge what the trace recorded."""
    used_limit = limit or trace_limit()
    os.makedirs(workdir, mode=0o700, exist_ok=True)
    traces: Dict[str, str] = {}
    errors: List[str] = []
    for spec in FIXTURE_SPECS:
        trace_path = os.path.join(workdir, f"{spec['name']}.trace")
        leg_limit = spec["limit"] or used_limit
        command = [
            "strace", "-f", "-v", f"-s{leg_limit}",
            "-e", "trace=execve,execveat",
            "-o", trace_path,
            sys.executable or "python3", os.path.abspath(__file__),
            f"exec-{spec['syscall']}", *spec["arguments"],
        ]
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=FIXTURE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            errors.append(
                f"{spec['name']}: the traced helper did not exit within "
                f"{FIXTURE_TIMEOUT_SECONDS} s"
            )
            proc = None
        if proc is not None and proc.returncode != 0:
            errors.append(
                f"{spec['name']}: the traced helper exited {proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:300]}"
            )
        try:
            with open(trace_path, "r", errors="replace") as handle:
                traces[spec["name"]] = handle.read()
        except OSError:
            traces[spec["name"]] = ""
        finally:
            _remove(trace_path)
    facts = judge_fixtures(used_limit, traces)
    facts["errors"] = errors + facts["errors"]
    if errors:
        facts["status"] = "FAIL"
    return facts


# --------------------------------------------------------------- the helper
def _execveat(path: str, argv: Sequence[str]) -> None:
    """Perform a real ``execveat``, so the trace holds one to inspect."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    encoded = [element.encode("utf-8", "surrogateescape") for element in argv]
    vector = (ctypes.c_char_p * (len(encoded) + 1))(*encoded, None)
    environment = (ctypes.c_char_p * 1)(None)
    at_fdcwd = -100
    entry = getattr(libc, "execveat", None)
    if entry is not None:
        entry(ctypes.c_int(at_fdcwd), ctypes.c_char_p(path.encode()), vector, environment, ctypes.c_int(0))
    else:
        # Older libc versions ship no wrapper; the raw numbers are the same
        # syscall the wrapper would make.
        numbers = {"x86_64": 322, "aarch64": 281}
        number = numbers.get(os.uname().machine)
        if number is None:
            raise OSError(f"execveat is not available on {os.uname().machine}")
        libc.syscall(
            ctypes.c_long(number), ctypes.c_int(at_fdcwd), ctypes.c_char_p(path.encode()),
            vector, environment, ctypes.c_int(0),
        )
    errno = ctypes.get_errno()
    raise OSError(errno, os.strerror(errno))


def _exec_helper(mode: str, arguments: Sequence[str]) -> None:
    executable = sys.executable or "/usr/bin/python3"
    argv = [os.path.basename(executable), "-c", "pass", *arguments]
    if mode == "execve":
        os.execv(executable, argv)
    elif mode == "execveat":
        _execveat(executable, argv)
    raise SystemExit(f"unknown helper mode {mode!r}")


# ----------------------------------------------------------------- in-container driver
def deliver(podman: Any, container: str) -> Dict[str, Any]:
    """Stream this file into the Master and mark it executable.

    The source travels over stdin and holds no secret; the secret reaches the
    scanner the same way, so neither is an argv entry anywhere.
    """
    result: Dict[str, Any] = {"delivered": False, "path": PROBE_PATH, "error": ""}
    prepared = podman.exec_bash(container, probe_directory_script(), check=False)
    if prepared.returncode != 0:
        result["error"] = (
            f"the observer directory could not be prepared in {container}: "
            f"{(prepared.stderr or prepared.stdout).strip()[:400]}"
        )
        return result
    source = Path(__file__).read_text(encoding="utf-8")
    written = podman.exec_bash(
        container,
        f"cat > {shlex.quote(PROBE_PATH)} && chmod 0700 {shlex.quote(PROBE_PATH)}",
        check=False,
        input_text=source,
    )
    if written.returncode != 0:
        result["error"] = f"the observer could not be written in {container}: {written.stderr.strip()[:400]}"
        return result
    result["delivered"] = True
    return result


def _last_json(text: str) -> Optional[Dict[str, Any]]:
    for line in reversed((text or "").strip().splitlines()):
        candidate = line.strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                return None
    return None


def run_fixtures(podman: Any, container: str) -> Dict[str, Any]:
    proc = podman.exec(
        container, ["python3", PROBE_PATH, "fixtures"],
        check=False, timeout=FIXTURE_TIMEOUT_SECONDS,
    )
    facts = _last_json(proc.stdout)
    if facts is None:
        return {
            "status": "FAIL",
            "fixtures": [],
            "errors": [
                "the acceptance fixtures printed no JSON fact line: "
                f"{(proc.stderr or proc.stdout).strip()[:400]}"
            ],
        }
    return facts


def extract_secret(podman: Any, container: str) -> Tuple[str, str]:
    """The Master's own SECRET_KEY, read through the product's extractor.

    Returns ``(value, error)``; the value is only ever handed to the scanner
    over stdin and is never rendered, recorded or passed as an argument.
    """
    proc = podman.exec_bash(
        container,
        "source /repo/modules/node.sh && extract_secret_key",
        check=False, timeout=SECRET_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return "", (
            "the Master could not print its own SECRET_KEY: "
            f"{(proc.stderr or proc.stdout).strip()[:400] or 'no output'}"
        )
    return (proc.stdout or "").strip(), ""


def scan(podman: Any, container: str, secret: str, client: str) -> Dict[str, Any]:
    proc = podman.exec(
        container, ["python3", PROBE_PATH, "scan", TRACE_PATH, client],
        check=False, input_text=secret, timeout=SCAN_TIMEOUT_SECONDS,
    )
    facts = _last_json(proc.stdout)
    if facts is None:
        return {
            "status": "INCOMPLETE",
            "exec_count": 0,
            "execve_count": 0,
            "execveat_count": 0,
            "ssh_execs": 0,
            "secret_found": False,
            "truncated": True,
            "abbreviated": True,
            "trace_bytes": 0,
            "trace_removed": False,
            "errors": [
                "the scanner printed no JSON fact line: "
                f"{(proc.stderr or proc.stdout).strip()[:400]}"
            ],
        }
    return facts


def ensure_strace(podman: Any, container: str) -> Dict[str, Any]:
    """Install strace where the trace is taken and learn its limit.

    The live runner does this on the Master before the dispatch; the container
    copy does the same inside the Master. A failure is reported in the facts
    rather than raised, so a missing observer never turns an unobserved
    deployment into a failed one.
    """
    facts: Dict[str, Any] = {
        "ok": False,
        "installed": False,
        "version": "",
        "limit": 0,
        "client": "",
        "error": "",
    }
    present = podman.exec(container, ["bash", "-lc", "command -v strace"], check=False)
    if present.returncode != 0:
        installed = podman.exec_bash(
            container, install_strace_script(), check=False, timeout=INSTALL_TIMEOUT_SECONDS,
        )
        if installed.returncode != 0:
            facts["error"] = (
                "strace could not be installed in the Master: "
                f"{(installed.stderr or installed.stdout).strip()[:400]}"
            )
            return facts
        facts["installed"] = True
    version = podman.exec_bash(container, "strace -V | head -n1", check=False)
    if version.returncode != 0:
        facts["error"] = "the installed strace could not report its version"
        return facts
    facts["version"] = (version.stdout or "").strip().splitlines()[0] if version.stdout.strip() else ""
    flags = podman.exec_bash(container, flags_script(), check=False)
    if flags.returncode != 0:
        facts["error"] = "the installed strace does not support -f, -v, -s, execve,execveat"
        return facts
    limit = podman.exec_bash(container, limit_script(), check=False)
    try:
        facts["limit"] = int((limit.stdout or "").strip())
    except ValueError:
        facts["error"] = f"the Master reported no page size: {(limit.stderr or limit.stdout).strip()[:200]}"
        return facts
    client = podman.exec_bash(container, client_script(), check=False)
    facts["client"] = (client.stdout or "").strip()
    if not facts["client"]:
        facts["error"] = (
            "the Master resolves no client for its remote dispatch, so the deployment's "
            f"own dispatch cannot be looked for in the trace: {(client.stderr or '').strip()[:200]}"
        )
        return facts
    facts["ok"] = facts["limit"] > 0
    return facts


# --------------------------------------------------------------------- entry
def main(argv: Sequence[str]) -> int:
    if not argv:
        print(json.dumps({"status": "FAIL", "errors": ["no mode was given"]}))
        return 2
    mode = argv[0]
    if mode == "fixtures":
        facts = acceptance_fixtures()
        print(json.dumps(facts))
        return 0 if facts["status"] == "PASS" else 1
    if mode.startswith("exec-"):
        _exec_helper(mode[len("exec-"):], argv[1:])
        return 0
    if mode == "scan":
        trace_path = argv[1] if len(argv) > 1 else TRACE_PATH
        client = argv[2] if len(argv) > 2 else ""
        secret = sys.stdin.read().strip()
        print(json.dumps(scan_trace_file(trace_path, [secret] if secret else [], client)))
        return 0
    print(json.dumps({"status": "FAIL", "errors": [f"unknown mode {mode!r}"]}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
