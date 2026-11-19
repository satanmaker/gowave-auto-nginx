"""Panel REST API client for Live VPS E2E testing.
Interacts with the real GoWave Panel over HTTPS using the mode-specific CA bundle and strict timeouts.
"""
from __future__ import annotations

import os
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.api_client import GoWaveClient, GoWaveAPIError
from .redaction import register_secret


def configured_api_timeout() -> int:
    """The per-attempt bound the rest of the controller reads from ``API_TIMEOUT``.

    A caller that omits the optional argument gets this value rather than a
    second literal: the live runner passes ``config["API_TIMEOUT"]`` explicitly,
    and a default that drifted away from it would make "the client honours the
    configured timeout" true only for the one code path that remembered to pass
    it.
    """
    from .config import parse_positive_int

    return parse_positive_int(os.environ.get("API_TIMEOUT", "15"), "API_TIMEOUT")


class E2EPanelClient:
    def __init__(
        self,
        panel_domain: str,
        ssl_context: Optional[ssl.SSLContext] = None,
        timeout: Optional[int] = None,
    ):
        self.panel_domain = panel_domain
        self.base_url = f"https://{panel_domain}"
        self.ssl_context = ssl_context
        # ``None`` keeps the caller's current behaviour: ``GoWaveClient`` without
        # a context uses the system store, exactly as it did before the live
        # controller started handing in the run's own bundle.
        self.timeout = configured_api_timeout() if timeout is None else timeout
        self.client = GoWaveClient(
            base_url=self.base_url,
            ssl_context=self.ssl_context,
            timeout=self.timeout,
        )

    def login(self, username: str, password: str) -> str:
        """Authenticate with username and password, storing accessToken."""
        payload = {"username": username, "password": password}
        resp = self.client.request(
            method="POST",
            endpoint="/api/auth/login",
            data=payload,
            authenticate=False,
        )
        token = None
        if isinstance(resp, dict):
            token = resp.get("accessToken") or resp.get("token") or (resp.get("response", {}).get("accessToken"))
        if not token:
            raise GoWaveAPIError("Login response did not contain an accessToken")
        self.client.token = token
        return token

    def get_nodes(self) -> List[Dict[str, Any]]:
        resp = self.client.request("GET", "/api/nodes")
        data = resp.get("response", resp) if isinstance(resp, dict) else resp
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    def get_config_profiles(self) -> List[Dict[str, Any]]:
        resp = self.client.request("GET", "/api/config-profiles")
        data = resp.get("response", resp) if isinstance(resp, dict) else resp
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    def get_internal_squads(self) -> List[Dict[str, Any]]:
        resp = self.client.request("GET", "/api/internal-squads")
        data = resp.get("response", resp) if isinstance(resp, dict) else resp
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    def get_hosts(self) -> List[Dict[str, Any]]:
        resp = self.client.request("GET", "/api/hosts")
        data = resp.get("response", resp) if isinstance(resp, dict) else resp
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    def get_user_by_username(self, username: str = "default-user") -> Dict[str, Any]:
        resp = self.client.request("GET", f"/api/users/by-username/{username}")
        data = resp.get("response", resp) if isinstance(resp, dict) else resp
        if isinstance(data, dict):
            return data
        raise GoWaveAPIError("User lookup returned an invalid response")

    def poll_worker_ready(
        self,
        worker_name: str = "worker-1",
        timeout: int = 120,
        poll_interval: int = 5,
    ) -> bool:
        """Poll GET /api/nodes until worker_name appears with isConnected == True."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                nodes = self.get_nodes()
                for n in nodes:
                    if n.get("name") == worker_name:
                        if n.get("isConnected") is True:
                            return True
            except Exception:
                pass
            time.sleep(poll_interval)
        return False


def read_master_credentials(master_ssh: Any) -> Dict[str, str]:
    """Read generated Panel credentials without putting secret values in argv.

    The file is trusted only when it is root-owned and has exact mode 0600.
    Values are registered for redaction immediately after parsing.
    """
    result = master_ssh.run(
        "test -f /root/gowave-credentials.txt && test ! -L /root/gowave-credentials.txt && "
        "test \"$(stat -c '%F:%a:%u' /root/gowave-credentials.txt)\" = 'regular file:600:0' && "
        "cat -- /root/gowave-credentials.txt",
        timeout=10,
    )
    if not result.ok:
        raise GoWaveAPIError(
            "Cannot read root-owned mode-0600 /root/gowave-credentials.txt on Master"
        )

    values: Dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("ADMIN_USERNAME", "ADMIN_PASSWORD", "SCOPED_API_TOKEN"):
            values[key] = value.strip()

    missing = [key for key in ("ADMIN_USERNAME", "ADMIN_PASSWORD", "SCOPED_API_TOKEN")
               if not values.get(key)]
    if missing:
        raise GoWaveAPIError(
            "Master credentials file is missing required fields: " + ", ".join(missing)
        )

    register_secret(values["ADMIN_PASSWORD"])
    register_secret(values["SCOPED_API_TOKEN"])
    return values
