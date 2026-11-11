"""OpenSSH subprocess wrapper enforcing zero-leak credentials, strict host key checking,
and isolated stdin delivery.
"""
from __future__ import annotations

import atexit
import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .redaction import redact, _SECRETS


@dataclass
class SSHResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def assert_no_secrets_in_argv(args: List[str]) -> None:
    """Zero-leak argv validation: scan argv elements for known secrets or prohibited secret flags."""
    for arg in args:
        # Check against registered literal secrets
        for sec in _SECRETS:
            if sec and sec in arg:
                raise ValueError(
                    "Zero-leak violation: registered secret detected in command-line argument"
                )

        # Prohibit dangerous CLI flags that commonly accept passwords/tokens
        lower = arg.lower()
        if any(
            flag in lower
            for flag in [
                "password=",
                "secret_key=",
                "admin_password=",
                "scoped_api_token=",
                "token=",
            ]
        ):
            raise ValueError(
                "Zero-leak violation: prohibited credential parameter detected in command-line argument"
            )


class SSHClient:
    def __init__(
        self,
        host: str,
        port: int = 22,
        user: str = "root",
        key_path: Optional[str | Path] = None,
        known_hosts: Optional[str | Path] = None,
        connect_timeout: int = 10,
        multiplex: bool = True,
        control_persist: int = 300,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.key_path = str(Path(key_path).resolve()) if key_path else None
        self.known_hosts = str(Path(known_hosts).resolve()) if known_hosts else None
        self.connect_timeout = connect_timeout
        self.multiplex = multiplex
        self.control_persist = control_persist
        self._control_dir: Optional[str] = None
        self._control_path: Optional[str] = None
        if multiplex:
            atexit.register(self.close)

    def _control_socket_path(self) -> str:
        """Return a short socket path inside a private per-client directory.

        A fresh directory per client process means a socket left behind by an earlier
        or killed run can never be reused; ControlPersist keeps the authenticated
        channel only for this client's lifetime, which close() ends explicitly.
        """
        if self._control_path is None:
            directory = tempfile.mkdtemp(prefix="gowave-ssh-")
            os.chmod(directory, 0o700)
            self._control_dir = directory
            digest = hashlib.sha256(
                f"{self.user}@{self.host}:{self.port}".encode("utf-8")
            ).hexdigest()[:12]
            self._control_path = os.path.join(directory, digest)
        return self._control_path

    def close(self) -> None:
        """Release the multiplexed master connection and remove its private socket."""
        control_path = self._control_path
        if control_path:
            try:
                subprocess.run(
                    ["ssh", "-F", "/dev/null", "-o", f"ControlPath={control_path}",
                     "-O", "exit", f"{self.user}@{self.host}"],
                    capture_output=True,
                    timeout=10,
                    shell=False,
                )
            except Exception:
                pass
        if self._control_dir:
            shutil.rmtree(self._control_dir, ignore_errors=True)
        self._control_dir = None
        self._control_path = None

    def _base_ssh_options(self) -> List[str]:
        """Disable ambient SSH configuration and trust sources; use only explicit pins."""
        known_hosts = self.known_hosts or "/dev/null"
        options = [
            "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o", "VerifyHostKeyDNS=no",
            "-o", "CanonicalizeHostname=no",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "PermitLocalCommand=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "GSSAPIAuthentication=no",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
        ]
        if self.multiplex:
            options.extend([
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={self._control_socket_path()}",
                "-o", f"ControlPersist={self.control_persist}",
            ])
        else:
            options.extend(["-o", "ControlMaster=no", "-o", "ControlPath=none"])
        return options

    def _build_ssh_cmd(self, remote_cmd: Optional[str] = None) -> List[str]:
        cmd = ["ssh", "-p", str(self.port), *self._base_ssh_options()]
        if self.key_path:
            cmd.extend(["-i", self.key_path])

        cmd.append(f"{self.user}@{self.host}")
        if remote_cmd is not None:
            cmd.append(remote_cmd)
        return cmd

    def run(
        self,
        remote_cmd: str,
        input_data: Optional[str | bytes] = None,
        timeout: int = 60,
    ) -> SSHResult:
        cmd = self._build_ssh_cmd(remote_cmd)
        assert_no_secrets_in_argv(cmd)

        stdin_bytes = None
        if input_data is not None:
            if isinstance(input_data, str):
                stdin_bytes = input_data.encode("utf-8")
            else:
                stdin_bytes = input_data

        try:
            proc = subprocess.run(
                cmd,
                input=stdin_bytes,
                capture_output=True,
                timeout=timeout,
                shell=False,
            )
            stdout = redact(proc.stdout.decode("utf-8", errors="replace"))
            stderr = redact(proc.stderr.decode("utf-8", errors="replace"))
            return SSHResult(returncode=proc.returncode, stdout=stdout, stderr=stderr)
        except subprocess.TimeoutExpired as e:
            stdout = redact(e.stdout.decode("utf-8", errors="replace") if e.stdout else "")
            stderr = redact(e.stderr.decode("utf-8", errors="replace") if e.stderr else "")
            return SSHResult(
                returncode=124,
                stdout=stdout,
                stderr=stderr + f"\nCommand timed out after {timeout} seconds",
            )
        except Exception as e:
            return SSHResult(returncode=1, stdout="", stderr=redact(str(e)))

    def copy_to_remote(
        self,
        local_path: str | Path,
        remote_path: str,
        timeout: int = 60,
    ) -> SSHResult:
        lp = str(Path(local_path).resolve())
        cmd = ["scp", "-P", str(self.port), *self._base_ssh_options()]
        if self.key_path:
            cmd.extend(["-i", self.key_path])

        cmd.extend([lp, f"{self.user}@{self.host}:{remote_path}"])
        assert_no_secrets_in_argv(cmd)

        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, shell=False)
            stdout = redact(proc.stdout.decode("utf-8", errors="replace"))
            stderr = redact(proc.stderr.decode("utf-8", errors="replace"))
            return SSHResult(returncode=proc.returncode, stdout=stdout, stderr=stderr)
        except Exception as e:
            return SSHResult(returncode=1, stdout="", stderr=redact(str(e)))
