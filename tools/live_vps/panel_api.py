"""Panel REST API client for Live VPS E2E testing.
Interacts with the real GoWave Panel over HTTPS using the mode-specific CA bundle and strict timeouts.
"""
from __future__ import annotations

import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.api_client import GoWaveClient, GoWaveAPIError


class E2EPanelClient:
    def __init__(
        self,
        panel_domain: str,
        ssl_context: ssl.SSLContext,
        timeout: int = 15,
    ):
        self.panel_domain = panel_domain
        self.base_url = f"https://{panel_domain}"
        self.ssl_context = ssl_context
        self.timeout = timeout
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
            raise GoWaveAPIError(f"Login response did not contain an accessToken: {resp}")
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
        raise GoWaveAPIError(f"User {username} not found or invalid format: {resp}")

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
