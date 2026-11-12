"""Run-scoped Podman resource management with label-scoped cleanup.

Every resource created by the suite carries the run label. Cleanup filters on
that label and never removes host containers, networks, volumes, or firewall
state that the run did not create.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .images import ImageLockError, resolve
from .runner import RunContext


class PodmanUnavailable(RuntimeError):
    pass


class UnpinnedImageError(RuntimeError):
    pass


def podman_binary() -> str:
    binary = shutil.which("podman")
    if not binary:
        raise PodmanUnavailable("Podman is not installed; the Podman E2E gate cannot run.")
    return binary


def require_rootful() -> None:
    podman_binary()
    if os.geteuid() != 0:
        raise PodmanUnavailable("Rootful Podman is required (run with sudo) for firewall and service assertions.")
    info = subprocess.run(
        [podman_binary(), "info", "--format", "{{.Host.Security.Rootless}}"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if info.returncode != 0 or info.stdout.strip() != "false":
        raise PodmanUnavailable("Rootful Podman is required; rootless mode cannot prove INPUT firewall isolation.")


STALE_AFTER_SECONDS = 6 * 3600
DEFAULT_COMMAND_TIMEOUT = 300


def wait_until(
    predicate,
    timeout_seconds: float,
    description: str,
    interval_seconds: float = 0.5,
    clock=time.monotonic,
    sleep=time.sleep,
) -> bool:
    """Bounded readiness poll. There is no unbounded wait anywhere in the suite.

    The deadline is absolute, the interval is clamped so the last poll still lands
    inside the deadline, and a non-positive timeout is a programming error.
    """
    if timeout_seconds <= 0:
        raise ValueError(f"{description}: readiness timeout must be positive")
    deadline = clock() + timeout_seconds
    while clock() < deadline:
        if predicate():
            return True
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleep(min(interval_seconds, remaining))
    return predicate()


def _get(item: Dict[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in item.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


class Podman:
    def __init__(self, context: RunContext) -> None:
        self.context = context
        self.binary = podman_binary()
        self._built_images: set[str] = set()
        self._started_epoch = int(time.time())

    def _run(
        self,
        args: Sequence[str],
        check: bool = True,
        input_text: Optional[str] = None,
        timeout: int = DEFAULT_COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(
                [self.binary, *args],
                capture_output=True, text=True, input=input_text, check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"podman {' '.join(args)} did not finish within {timeout}s"
            ) from exc
        if check and proc.returncode != 0:
            raise RuntimeError(f"podman {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return proc

    def _ownership_labels(self) -> List[str]:
        return [
            "--label", f"gowave.e2e.run={self.context.run_id}",
            "--label", f"gowave.e2e.topology={self.context.topology}",
            "--label", f"gowave.e2e.started={self._started_epoch}",
        ]

    def network_create(
        self,
        name: str,
        subnet: Optional[str] = None,
        disable_dns: bool = False,
        internal: bool = False,
    ) -> str:
        """Create the run network.

        ``disable_dns`` stops netavark from installing its own resolver at the
        gateway. That resolver ignores per-container ``--dns`` entirely, which
        would make the fixture zone unreachable as the authoritative source.

        ``internal`` leaves the network without a gateway, so it carries a
        connected route and nothing else: no default route can displace the run
        network's, and no packet addressed into it can be forwarded off the host.
        """
        args = ["network", "create", *self._ownership_labels()]
        if subnet:
            args += ["--subnet", subnet]
        if disable_dns:
            args.append("--disable-dns")
        if internal:
            args.append("--internal")
        args.append(name)
        self._run(args)
        return name

    def network_connect(self, name: str, network: str, ip: Optional[str] = None) -> str:
        """Attach a running container to another run network.

        A second interface is how one role carries both a private control
        address and a public one; attaching after start keeps the container's
        original default route and resolver untouched.
        """
        args = ["network", "connect"]
        if ip:
            args += ["--ip", ip]
        args += [network, name]
        self._run(args)
        return name

    def network_subnets(self) -> List[str]:
        """Subnets already claimed by Podman networks, so a new /24 never collides."""
        listing = self._run(["network", "ls", "--format", "{{.Name}}"], check=False)
        subnets: List[str] = []
        for name in (listing.stdout or "").split():
            inspected = self._run(["network", "inspect", name], check=False)
            if inspected.returncode != 0:
                continue
            try:
                data = json.loads(inspected.stdout or "[]")
            except json.JSONDecodeError:
                continue
            for network in data if isinstance(data, list) else []:
                for entry in (network.get("subnets") or []):
                    subnet = entry.get("subnet") if isinstance(entry, dict) else None
                    if subnet:
                        subnets.append(str(subnet))
        return subnets

    def volume_create(self, name: str) -> str:
        self._run(["volume", "create", *self._ownership_labels(), name])
        return name

    def ensure_image(self, alias: str) -> str:
        """Pull an alias at its locked digest and return the immutable reference."""
        if alias in self._built_images:
            return alias
        if "@" in alias or ":" in alias:
            raise UnpinnedImageError(
                f"{alias!r} is a raw reference; pass an alias pinned in tests/cases/images.lock.yaml"
            )
        try:
            pinned = resolve(alias)
        except ImageLockError as exc:
            raise UnpinnedImageError(str(exc)) from exc
        repository, digest = pinned.rsplit("@", 1)
        self._run(["pull", pinned])
        inspected = self._run(["image", "inspect", "--format", "{{json .RepoDigests}}", pinned])
        digests = json.loads(inspected.stdout or "[]")
        if not any(str(entry).endswith(f"@{digest}") for entry in digests):
            raise UnpinnedImageError(
                f"{alias}: pulled {pinned} but Podman reports digests {digests}; refusing to run an unverified image"
            )
        self.context.environment.setdefault("images_resolved", {})[alias] = f"{repository}@{digest}"
        return pinned

    def build(
        self,
        tag: str,
        base_alias: str,
        containerfile: Path,
        context_dir: Path,
        build_args: Optional[Dict[str, str]] = None,
    ) -> str:
        """Build a testbed image from a digest-pinned base and label it for cleanup."""
        base = self.ensure_image(base_alias)
        arguments = ["--build-arg", f"BASE_IMAGE={base}"]
        for key, value in (build_args or {}).items():
            arguments += ["--build-arg", f"{key}={value}"]
        self._run([
            "build", "-t", tag, "-f", str(containerfile),
            *self._ownership_labels(),
            *arguments,
            str(context_dir),
        ])
        self.context.add_cleanup(lambda: self._run(["rmi", "-f", tag], check=False))
        self._built_images.add(tag)
        return tag

    def run(
        self,
        name: str,
        image_alias: str,
        network: str,
        aliases: Sequence[str] = (),
        privileged: bool = True,
        volumes: Sequence[str] = (),
        environment: Optional[Dict[str, str]] = None,
        command: Optional[Sequence[str]] = None,
        read_only_repo: bool = True,
        systemd: str = "always",
        extra_args: Sequence[str] = (),
    ) -> str:
        args = [
            "run", "-d", "--name", name,
            *self._ownership_labels(),
            "--network", network,
            "--hostname", aliases[0] if aliases else name,
            f"--systemd={systemd}",
        ]
        if privileged:
            args.append("--privileged")
        for alias in aliases:
            args += ["--network-alias", alias]
        for volume in volumes:
            args += ["-v", volume]
        if read_only_repo:
            args += ["-v", f"{Path(__file__).resolve().parent.parent.parent}:/repo:ro"]
        for key, value in (environment or {}).items():
            args += ["-e", f"{key}={value}"]
        args.extend(extra_args)
        args.append(self.ensure_image(image_alias))
        if command:
            args.extend(command)
        self._run(args)
        return name

    def exec(
        self,
        name: str,
        argv: Sequence[str],
        check: bool = True,
        input_text: Optional[str] = None,
        timeout: int = DEFAULT_COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        # ``podman exec`` attaches stdin only with ``-i``; without it the container
        # reads EOF, so a command like ``cat >> file`` succeeds and writes nothing.
        # Delivery over stdin is how secrets and keys avoid argv, so the flag is
        # mandatory whenever there is something to deliver.
        attached = ["-i"] if input_text is not None else []
        return self._run(["exec", *attached, name, *argv], check=check, input_text=input_text, timeout=timeout)

    def exec_bash(
        self,
        name: str,
        script: str,
        check: bool = True,
        input_text: Optional[str] = None,
        timeout: int = DEFAULT_COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        return self.exec(name, ["bash", "-lc", script], check=check, input_text=input_text, timeout=timeout)

    def wait_systemd(self, name: str, timeout_seconds: int = 90) -> str:
        observed = {"state": "unknown"}

        def ready() -> bool:
            proc = self.exec(name, ["systemctl", "is-system-running"], check=False)
            observed["state"] = proc.stdout.strip() or proc.stderr.strip() or "unknown"
            return observed["state"] in ("running", "degraded")

        if wait_until(ready, timeout_seconds, f"systemd readiness in {name}"):
            return observed["state"]
        logs = self._run(["logs", name], check=False)
        raise RuntimeError(
            f"systemd did not become ready in {name} within {timeout_seconds}s (last state: {observed['state']})\n"
            f"{logs.stdout[-2000:]}{logs.stderr[-2000:]}"
        )

    def wait_tcp(self, name: str, host: str, port: int, timeout_seconds: int = 60) -> None:
        script = f"timeout 1 bash -c '</dev/tcp/{host}/{port}'"
        if not wait_until(
            lambda: self.exec_bash(name, script, check=False).returncode == 0,
            timeout_seconds,
            f"{host}:{port} reachability from {name}",
        ):
            raise RuntimeError(f"{host}:{port} was not reachable from {name} within {timeout_seconds}s")

    def address(self, name: str, network: Optional[str] = None) -> str:
        fmt = (
            '{{range $k, $v := .NetworkSettings.Networks}}'
            '{{if eq $k "' + network + '"}}{{$v.IPAddress}}{{end}}{{end}}'
            if network else
            '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
        )
        proc = self._run(["inspect", "--format", fmt, name])
        address = proc.stdout.strip()
        if not address:
            raise RuntimeError(f"Could not determine the network address of {name}")
        return address

    def image_reference(self, image: str) -> Dict[str, str]:
        proc = self._run(["image", "inspect", "--format", "{{json .RepoDigests}}", image], check=False)
        if proc.returncode != 0:
            return {"image": image, "digest": ""}
        digests = json.loads(proc.stdout or "[]")
        return {"image": image, "digest": digests[0] if digests else ""}

    def stale_run_resources(
        self,
        max_age_seconds: int = STALE_AFTER_SECONDS,
        now: Optional[int] = None,
    ) -> Dict[str, List[str]]:
        """Owned resources of older runs, keyed by run id, that are safe to reclaim."""
        moment = int(now if now is not None else time.time())
        stale: Dict[str, List[str]] = {}
        for kind, args, id_fields in (
            ("container", ["ps", "-a", "--format", "json"], ("Id", "ID", "Names", "Name")),
            ("volume", ["volume", "ls", "--format", "json"], ("Name", "name")),
            ("network", ["network", "ls", "--format", "json"], ("Id", "id", "Name", "name")),
        ):
            proc = self._run(args, check=False)
            if proc.returncode != 0:
                continue
            try:
                items = json.loads(proc.stdout or "[]")
            except json.JSONDecodeError:
                continue
            for item in items:
                labels = {str(key).lower(): str(value) for key, value in (_get(item, "Labels") or {}).items()}
                run_id = labels.get("gowave.e2e.run")
                started = labels.get("gowave.e2e.started")
                if not run_id or run_id == self.context.run_id:
                    continue
                try:
                    age = moment - int(started)
                except (TypeError, ValueError):
                    continue
                if age < max_age_seconds:
                    continue
                identifier = _get(item, *id_fields)
                if isinstance(identifier, list):
                    identifier = identifier[0] if identifier else None
                if not identifier:
                    continue
                stale.setdefault(run_id, []).append(f"{kind}:{identifier}")
        return stale

    def remove_stale_runs(
        self,
        max_age_seconds: int = STALE_AFTER_SECONDS,
        now: Optional[int] = None,
    ) -> List[str]:
        """Reclaim resources left behind by a crashed or killed run of this suite only."""
        removed: List[str] = []
        for resources in self.stale_run_resources(max_age_seconds, now).values():
            for reference in resources:
                kind, identifier = reference.split(":", 1)
                argv = {
                    "container": ["rm", "-f"],
                    "volume": ["volume", "rm", "-f"],
                    "network": ["network", "rm", "-f"],
                }[kind]
                self._run([*argv, identifier], check=False)
                removed.append(reference)
        return removed

    def remove_run_resources(self) -> List[str]:
        label = f"gowave.e2e.run={self.context.run_id}"
        removed: List[str] = []
        for kind, args in (
            ("container", ["ps", "-aq", "--filter", f"label={label}"]),
            ("volume", ["volume", "ls", "-q", "--filter", f"label={label}"]),
            ("network", ["network", "ls", "-q", "--filter", f"label={label}"]),
        ):
            proc = self._run(args, check=False)
            identifiers = [line for line in proc.stdout.splitlines() if line.strip()]
            if identifiers:
                self._run([kind, "rm", "-f", *identifiers] if kind != "container" else ["rm", "-f", *identifiers], check=False)
                removed.extend(identifiers)
        return removed

    def register_cleanup(self) -> None:
        self.context.add_cleanup(self.remove_run_resources)
