"""OpenSSH subprocess wrapper enforcing zero-leak credentials, strict host key checking,
and isolated stdin delivery.
"""
from __future__ import annotations

import os
import subprocess
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
                    f"Zero-leak violation: secret detected in command-line argument: {arg[:4]}***"
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
                f"Zero-leak violation: argument '{arg}' appears to contain credential parameters in argv"
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
    ):
        self.host = host
        self.port = port
        self.user = user
        self.key_path = str(Path(key_path).resolve()) if key_path else None
        self.known_hosts = str(Path(known_hosts).resolve()) if known_hosts else None
        self.connect_timeout = connect_timeout

    def _build_ssh_cmd(self, remote_cmd: Optional[str] = None) -> List[str]:
        cmd = [
            "ssh",
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "ServerAliveInterval=15",
        ]
        if self.known_hosts:
            cmd.extend(["-o", f"UserKnownHostsFile={self.known_hosts}"])
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
        cmd = [
            "scp",
            "-P", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
        ]
        if self.known_hosts:
            cmd.extend(["-o", f"UserKnownHostsFile={self.known_hosts}"])
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
