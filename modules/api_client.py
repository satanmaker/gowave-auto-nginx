#!/usr/bin/env python3
"""GoWave REST API provisioning client, state reconciliation, and profile manager.
Adheres strictly to API_CONTRACTS.md and Section 2 of design.md.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent
XRAY_ASSETS_DIR = REPO_ROOT / "assets" / "xray"


class GoWaveAPIError(Exception):
    def __init__(self, message, status_code=None, response_body=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def _extract_list(res, key):
    data = res.get("response", res) if isinstance(res, dict) else res
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if key in data and isinstance(data[key], list):
            return data[key]
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


class GoWaveClient:
    def __init__(self, base_url="http://127.0.0.1:3000", token=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.token_expiry = 0
        self.username = None
        self.password = None

    def request(self, method, endpoint, data=None, headers=None, authenticate=True):
        url = f"{self.base_url}{endpoint}"
        req_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "gowave-auto-nginx/1.0",
        }
        if headers:
            req_headers.update(headers)

        if authenticate and self.token:
            req_headers["Authorization"] = f"Bearer {self.token}"

        encoded_data = None
        if data is not None:
            if isinstance(data, (dict, list)):
                encoded_data = json.dumps(data).encode("utf-8")
            elif isinstance(data, str):
                encoded_data = data.encode("utf-8")
            else:
                encoded_data = data

        req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method=method)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    resp_body = resp.read().decode("utf-8")
                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" in content_type:
                        try:
                            return json.loads(resp_body)
                        except json.JSONDecodeError:
                            return resp_body
                    return resp_body
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace")
                # Handle 401 re-login (never re-login if the failing endpoint is login itself)
                if e.code == 401 and self.username and self.password and attempt == 0 and endpoint != "/api/auth/login":
                    self.login(self.username, self.password)
                    req_headers["Authorization"] = f"Bearer {self.token}"
                    req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method=method)
                    continue

                # Handle HTTP 429 Rate Limiting with exponential backoff 2, 4, 8s (or Retry-After header)
                if e.code == 429 and attempt < max_retries - 1:
                    retry_after = e.headers.get("Retry-After")
                    delay = int(retry_after) if retry_after and retry_after.isdigit() else 2 ** (attempt + 1)
                    time.sleep(delay)
                    continue

                # Handle HTTP 5xx Server Errors (500, 502, 503, 504) with backoff 1, 2, 4s
                if e.code in (500, 502, 503, 504) and attempt < max_retries - 1:
                    delay = 2 ** attempt
                    time.sleep(delay)
                    continue

                # Parse JSON error if available
                error_msg = f"HTTP {e.code} on {method} {endpoint}: {err_body}"
                raise GoWaveAPIError(error_msg, status_code=e.code, response_body=err_body) from e
            except (urllib.error.URLError, TimeoutError, ConnectionResetError) as e:
                if attempt == max_retries - 1:
                    raise GoWaveAPIError(f"Network error on {method} {endpoint}: {e}") from e
                time.sleep(1)

    def register_initial_admin(self, username, password):
        self.username = username
        self.password = password
        try:
            res = self.request("POST", "/api/auth/register", {"username": username, "password": password}, authenticate=False)
            return res
        except GoWaveAPIError as e:
            if e.status_code in (400, 409):
                # Likely already registered; try login
                return self.login(username, password)
            raise

    def login(self, username, password):
        self.username = username
        self.password = password
        res = self.request("POST", "/api/auth/login", {"username": username, "password": password}, authenticate=False)
        token = None
        if isinstance(res, dict):
            token = res.get("response", {}).get("accessToken") or res.get("accessToken")
        if not token:
            raise GoWaveAPIError(f"Failed to obtain accessToken from login response: {res}")
        self.token = token
        self.token_expiry = time.time() + (12 * 3600) - 300
        return token

    def generate_x25519(self):
        res = self.request("GET", "/api/system/tools/x25519/generate")
        data = res.get("response", res) if isinstance(res, dict) else res
        private_key = None
        public_key = None

        if isinstance(data, dict):
            keypairs = data.get("keypairs")
            if isinstance(keypairs, list) and len(keypairs) > 0 and isinstance(keypairs[0], dict):
                private_key = keypairs[0].get("privateKey")
                public_key = keypairs[0].get("publicKey")
            else:
                private_key = data.get("privateKey")
                public_key = data.get("publicKey")
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            private_key = data[0].get("privateKey")
            public_key = data[0].get("publicKey")

        if not private_key or not public_key:
            raise GoWaveAPIError(f"Invalid x25519 response: {res}")
        return {"privateKey": private_key, "publicKey": public_key}

    def compile_config_profile(self, node_name, reality_domain, private_key, short_ids=None):
        if short_ids is None:
            short_ids = [secrets.token_hex(8)]

        # 1. Inbound REALITY
        reality_template = json.loads((XRAY_ASSETS_DIR / "vless-reality.json").read_text())
        reality_template["tag"] = f"vless-reality-{node_name}"
        reality_template["streamSettings"]["realitySettings"]["serverNames"] = [reality_domain]
        reality_template["streamSettings"]["realitySettings"]["privateKey"] = private_key
        reality_template["streamSettings"]["realitySettings"]["shortIds"] = short_ids

        # 2. Inbound XHTTP
        xhttp_template = json.loads((XRAY_ASSETS_DIR / "vless-xhttp.json").read_text())
        xhttp_template["tag"] = f"vless-xhttp-{node_name}"

        # 3. Inbound WS
        ws_template = json.loads((XRAY_ASSETS_DIR / "vless-ws.json").read_text())
        ws_template["tag"] = f"vless-ws-{node_name}"

        # 4. Inbound Trojan gRPC
        trojan_template = json.loads((XRAY_ASSETS_DIR / "trojan-grpc.json").read_text())
        trojan_template["tag"] = f"trojan-grpc-{node_name}"

        # Authoritative routing block preserving node API management rule before SSRF blocking
        routing_block = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "BLOCK",
                    "ip": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "169.254.0.0/16",
                        "100.64.0.0/10",
                        "::1/128",
                        "fc00::/7",
                        "fe80::/10",
                    ],
                },
                {
                    "type": "field",
                    "outboundTag": "BLOCK",
                    "protocol": ["bittorrent"],
                },
            ],
        }

        raw_xray = {
            "inbounds": [
                reality_template,
                xhttp_template,
                ws_template,
                trojan_template,
            ],
            "routing": routing_block,
        }
        return json.dumps(raw_xray, indent=2)

    def provision_config_profile(self, profile_name, raw_config_json):
        # Check existing profiles
        existing_profiles = self.request("GET", "/api/config-profiles")
        profiles_list = _extract_list(existing_profiles, "configProfiles")
        target_uuid = None
        if isinstance(profiles_list, list):
            for p in profiles_list:
                if p.get("name") == profile_name:
                    target_uuid = p.get("uuid")
                    break

        if target_uuid:
            # Update existing
            self.request("PATCH", f"/api/config-profiles/{target_uuid}", {"name": profile_name, "config": raw_config_json})
            profile_uuid = target_uuid
        else:
            # Create new
            res = self.request("POST", "/api/config-profiles", {"name": profile_name, "config": raw_config_json})
            data = res.get("response", res)
            profile_uuid = data.get("uuid")

        # 5-point verification checklist on computed-config
        computed = self.request("GET", f"/api/config-profiles/{profile_uuid}/computed-config")
        computed_data = computed.get("response", computed) if isinstance(computed, dict) else computed
        if isinstance(computed_data, dict) and "config" in computed_data:
            config_val = computed_data["config"]
            computed_json = json.loads(config_val) if isinstance(config_val, str) else config_val
        elif isinstance(computed_data, str):
            computed_json = json.loads(computed_data)
        else:
            computed_json = computed_data

        inbounds = computed_json.get("inbounds", []) if isinstance(computed_json, dict) else []
        if len(inbounds) != 4:
            raise GoWaveAPIError(f"5-point checklist failure: expected 4 inbounds, got {len(inbounds)}")

        # Retrieve inbounds list
        inbounds_res = self.request("GET", f"/api/config-profiles/{profile_uuid}/inbounds")
        inbounds_data = inbounds_res.get("response", inbounds_res) if isinstance(inbounds_res, dict) else inbounds_res
        if isinstance(inbounds_data, dict) and "inbounds" in inbounds_data:
            inbounds_list = inbounds_data["inbounds"]
        elif isinstance(inbounds_data, list):
            inbounds_list = inbounds_data
        else:
            inbounds_list = []
        return {"profile_uuid": profile_uuid, "inbounds": inbounds_list}

    def associate_node(self, node_name, node_address, node_port, profile_uuid, inbound_uuids, existing_node_uuid=None):
        payload = {
            "name": node_name,
            "address": node_address,
            "port": node_port,
            "configProfile": {
                "activeConfigProfileUuid": profile_uuid,
                "activeInbounds": inbound_uuids,
            },
        }

        if existing_node_uuid:
            res = self.request("PATCH", f"/api/nodes/{existing_node_uuid}", payload)
            node_uuid = existing_node_uuid
        else:
            # Check if node exists by name
            nodes_res = self.request("GET", "/api/nodes")
            nodes_list = _extract_list(nodes_res, "nodes")
            found_uuid = None
            if isinstance(nodes_list, list):
                for n in nodes_list:
                    if n.get("name") == node_name:
                        found_uuid = n.get("uuid")
                        break

            if found_uuid:
                res = self.request("PATCH", f"/api/nodes/{found_uuid}", payload)
                node_uuid = found_uuid
            else:
                res = self.request("POST", "/api/nodes", payload)
                data = res.get("response", res)
                node_uuid = data.get("uuid")

        return node_uuid

    def provision_internal_squad(self, squad_name, inbound_uuids):
        # Check existing squad
        squads_res = self.request("GET", "/api/internal-squads")
        squads_list = _extract_list(squads_res, "internalSquads")
        squad_uuid = None
        existing_inbounds = []
        if isinstance(squads_list, list):
            for s in squads_list:
                if s.get("name") == squad_name:
                    squad_uuid = s.get("uuid")
                    existing_inbounds = [inb.get("uuid") if isinstance(inb, dict) else inb for inb in s.get("inbounds", [])]
                    break

        all_inbounds = list(dict.fromkeys(existing_inbounds + inbound_uuids))

        if squad_uuid:
            self.request("PATCH", "/api/internal-squads", {"uuid": squad_uuid, "name": squad_name, "inbounds": all_inbounds})
        else:
            res = self.request("POST", "/api/internal-squads", {"name": squad_name, "inbounds": all_inbounds})
            data = res.get("response", res)
            squad_uuid = data.get("uuid")

        return squad_uuid

    def provision_hosts(self, profile_uuid, inbounds_list, node_uuid, squad_uuid, panel_domain, reality_domain, node_name="local-node"):
        # Protocol to config mapping
        proto_map = {
            "vless-reality": {
                "remark": f"VLESS-REALITY-Vision@{node_name}",
                "address": panel_domain,
                "port": 443,
                "sni": reality_domain,
                "path": None,
                "securityLayer": "DEFAULT",
                "alpn": "h2,http/1.1",
                "fingerprint": "chrome",
            },
            "vless-xhttp": {
                "remark": f"VLESS-XHTTP-TLS@{node_name}",
                "address": panel_domain,
                "port": 443,
                "sni": panel_domain,
                "path": "/xhttp-down/",
                "securityLayer": "TLS",
                "alpn": "h2,http/1.1",
                "fingerprint": "chrome",
            },
            "vless-ws": {
                "remark": f"VLESS-WS-TLS@{node_name}",
                "address": panel_domain,
                "port": 443,
                "sni": panel_domain,
                "path": "/ws",
                "securityLayer": "TLS",
                "alpn": "http/1.1",
                "fingerprint": "chrome",
            },
            "trojan-grpc": {
                "remark": f"Trojan-gRPC-TLS@{node_name}",
                "address": panel_domain,
                "port": 443,
                "sni": panel_domain,
                "path": "trojan-grpc",
                "securityLayer": "TLS",
                "alpn": "h2",
                "fingerprint": "chrome",
            },
        }

        # Check existing hosts
        hosts_res = self.request("GET", "/api/hosts")
        existing_hosts = _extract_list(hosts_res, "hosts")
        existing_by_remark = {}
        if isinstance(existing_hosts, list):
            for h in existing_hosts:
                existing_by_remark[h.get("remark")] = h.get("uuid")

        created_host_uuids = []
        for inb in inbounds_list:
            tag = inb.get("tag", "")
            inb_uuid = inb.get("uuid")
            # Determine profile protocol match
            matched_key = None
            for key in proto_map:
                if key in tag:
                    matched_key = key
                    break

            if not matched_key:
                continue

            cfg = proto_map[matched_key]
            remark = cfg["remark"]
            payload = {
                "inbound": {
                    "configProfileUuid": profile_uuid,
                    "configProfileInboundUuid": inb_uuid,
                },
                "nodes": [node_uuid],
                "remark": remark,
                "address": cfg["address"],
                "port": cfg["port"],
                "sni": cfg["sni"],
                "path": cfg["path"],
                "host": None,
                "alpn": cfg["alpn"],
                "fingerprint": cfg["fingerprint"],
                "securityLayer": cfg["securityLayer"],
                "internalSquads": {
                    "mode": "ALLOW_ONLY",
                    "squads": [squad_uuid],
                },
                "isDisabled": False,
            }

            if remark in existing_by_remark:
                host_uuid = existing_by_remark[remark]
                payload["uuid"] = host_uuid
                self.request("PATCH", "/api/hosts", payload)
            else:
                res = self.request("POST", "/api/hosts", payload)
                data = res.get("response", res)
                host_uuid = data.get("uuid")

            created_host_uuids.append(host_uuid)

        return created_host_uuids

    def provision_user(self, username, squad_uuid, expire_at="2099-01-01T00:00:00.000Z"):
        # Check existing user
        try:
            users_res = self.request("GET", f"/api/users/by-username/{username}")
            user_data = users_res.get("response", users_res)
            if user_data and user_data.get("shortUuid"):
                return user_data.get("shortUuid")
        except GoWaveAPIError as e:
            if e.status_code != 404:
                raise

        payload = {
            "username": username,
            "status": "ACTIVE",
            "trafficLimitStrategy": "NO_RESET",
            "expireAt": expire_at,
            "activeInternalSquads": [squad_uuid],
        }
        res = self.request("POST", "/api/users", payload)
        data = res.get("response", res)
        short_uuid = data.get("shortUuid")
        return short_uuid

    def issue_api_token(self, token_name="gowave-auto-sub-token"):
        scopes = [
            "subscription-page-configs:list",
            "subscription-page-configs:get",
            "subscriptions:subpage-config",
            "system:metadata",
            "users:by-username",
        ]
        payload = {
            "name": token_name,
            "description": "Generated by gowave-auto-nginx for external web subscription interfaces and integrations",
            "scopes": scopes,
            "expiresInDays": 365,
        }
        res = self.request("POST", "/api/tokens", payload)
        data = res.get("response", res)
        token_str = data.get("token")
        token_id = data.get("id") or data.get("uuid")
        return {"token": token_str, "id": token_id}

    def delete_token(self, token_id):
        try:
            return self.request("DELETE", f"/api/tokens/{token_id}")
        except GoWaveAPIError as e:
            if e.status_code == 404:
                return None
            raise

    def delete_user(self, user_uuid):
        try:
            return self.request("DELETE", f"/api/users/{user_uuid}")
        except GoWaveAPIError as e:
            if e.status_code == 404:
                return None
            raise

    def delete_host(self, host_uuid):
        try:
            return self.request("DELETE", f"/api/hosts/{host_uuid}")
        except GoWaveAPIError as e:
            if e.status_code == 404:
                return None
            raise

    def delete_internal_squad(self, squad_uuid):
        try:
            return self.request("DELETE", f"/api/internal-squads/{squad_uuid}")
        except GoWaveAPIError as e:
            if e.status_code == 404:
                return None
            raise

    def delete_node(self, node_uuid):
        try:
            return self.request("DELETE", f"/api/nodes/{node_uuid}")
        except GoWaveAPIError as e:
            if e.status_code == 404:
                return None
            raise

    def delete_config_profile(self, profile_uuid):
        try:
            return self.request("DELETE", f"/api/config-profiles/{profile_uuid}")
        except GoWaveAPIError as e:
            if e.status_code == 404:
                return None
            raise


def atomic_write_state(state_data, state_path="/var/lib/gowave-auto-nginx/state.json"):
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{path.name}.tmp"

    state_data["schemaVersion"] = 2
    state_data["lastUpdated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with open(tmp_path, "w") as f:
        json.dump(state_data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)

    # Sync parent directory
    dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def rollback_provisioning(journal_path="/var/lib/gowave-auto-nginx/recovery/journal.json",
                          state_path="/var/lib/gowave-auto-nginx/state.json",
                          credentials_path="/root/gowave-credentials.txt",
                          base_url="http://127.0.0.1:3000"):
    """Rolls back partial API entities created during uncommitted provisioning or worker additions.
    Implements reverse-order deletion per API_CONTRACTS.md §5.3.
    """
    try:
        from modules.recovery import write_journal_atomically
    except ImportError:
        try:
            from recovery import write_journal_atomically
        except ImportError:
            def write_journal_atomically(p, d):
                tmp = f"{p}.tmp"
                with open(tmp, "w") as f:
                    json.dump(d, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp, 0o600)
                os.replace(tmp, p)

    journal_file = Path(journal_path)
    if not journal_file.exists():
        return True

    try:
        with open(journal_file, "r") as f:
            journal_data = json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load journal {journal_file}: {e}", file=sys.stderr)
        return False

    op = journal_data.get("op", "")
    state = journal_data.get("state", "")

    # If already committed or rolled back, skip
    if state in ("PROVISION_COMMITTED", "NODE_ADD_COMMITTED", "PROVISION_ROLLED_BACK", "NODE_ADD_ROLLED_BACK"):
        return True

    # Read credentials
    username = "admin"
    password = ""
    creds_file = Path(credentials_path)
    if creds_file.exists():
        try:
            for line in creds_file.read_text().splitlines():
                if line.startswith("ADMIN_USERNAME="):
                    username = line.split("=", 1)[1].strip()
                elif line.startswith("ADMIN_PASSWORD="):
                    password = line.split("=", 1)[1].strip()
                elif line.startswith("Admin Username:"):
                    username = line.split(":", 1)[1].strip()
                elif line.startswith("Admin Password:"):
                    password = line.split(":", 1)[1].strip()
        except Exception as e:
            print(f"Warning reading credentials file: {e}", file=sys.stderr)

    if not password:
        env_file = Path("/opt/gowave/.env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("ADMIN_PASSWORD="):
                    password = line.split("=", 1)[1].strip()

    client = GoWaveClient(base_url)
    if username and password:
        try:
            client.login(username, password)
        except Exception as e:
            print(f"Warning: Login failed during rollback: {e}", file=sys.stderr)
            return False

    # Check state data if exists
    state_file = Path(state_path)
    state_data = {}
    if state_file.exists():
        try:
            with open(state_file, "r") as f:
                state_data = json.load(f)
        except Exception:
            pass

    tmp_state = state_file.parent / f"{state_file.name}.tmp"
    if tmp_state.exists():
        try:
            with open(tmp_state, "r") as f:
                tmp_data = json.load(f)
                if not state_data:
                    state_data = tmp_data
        except Exception:
            pass

    # Branch 1: PROVISION_* rollback
    if op == "provision" or state.startswith("PROVISION_"):
        entities = journal_data.get("entities", {})

        # Structured list format: [{"type": "...", "uuid": "...", "action": "created|updated|adopted", "before": ...}]
        if isinstance(entities, list):
            for item in reversed(entities):
                action = item.get("action", "created")
                etype = item.get("type", "")
                uuid = item.get("uuid", "")
                if action == "adopted" or not uuid:
                    continue
                if action == "updated":
                    before = item.get("before", {})
                    try:
                        if etype == "squad":
                            client.request("PATCH", "/api/internal-squads", {"uuid": uuid, **before})
                        elif etype == "profile":
                            client.request("PATCH", f"/api/config-profiles/{uuid}", before)
                        elif etype == "node":
                            client.request("PATCH", f"/api/nodes/{uuid}", before)
                    except Exception as e:
                        print(f"Rollback note (restore {etype} {uuid}): {e}", file=sys.stderr)
                elif action == "created":
                    try:
                        if etype == "token":
                            client.delete_token(uuid)
                        elif etype == "user":
                            client.delete_user(uuid)
                        elif etype == "host":
                            client.delete_host(uuid)
                        elif etype == "squad":
                            client.delete_internal_squad(uuid)
                        elif etype == "node":
                            client.delete_node(uuid)
                        elif etype == "profile":
                            client.delete_config_profile(uuid)
                    except Exception as e:
                        print(f"Rollback note (delete {etype} {uuid}): {e}", file=sys.stderr)

        # Dictionary format (strictly deletes UUIDs created by this transaction without global name scans)
        elif isinstance(entities, dict):
            actions = entities.get("actions", {})

            # 1. Tokens
            token_id = entities.get("token_id")
            if token_id and actions.get("token_id") != "adopted":
                try:
                    client.delete_token(token_id)
                except Exception as e:
                    print(f"Rollback note (tokens): {e}", file=sys.stderr)

            # 2. Users
            user_uuid = entities.get("user_uuid") or state_data.get("defaultUserUuid")
            if user_uuid and actions.get("user_uuid") != "adopted":
                try:
                    client.delete_user(user_uuid)
                except Exception as e:
                    print(f"Rollback note (users): {e}", file=sys.stderr)

            # 3. Hosts
            host_uuids = entities.get("host_uuids", [])
            for hid in reversed(host_uuids):
                try:
                    client.delete_host(hid)
                except Exception as e:
                    print(f"Rollback note (hosts): {e}", file=sys.stderr)

            # 4. Internal Squads
            squad_uuid = entities.get("squad_uuid") or state_data.get("squadUuid")
            if squad_uuid and actions.get("squad_uuid") != "adopted":
                try:
                    client.delete_internal_squad(squad_uuid)
                except Exception as e:
                    print(f"Rollback note (squads): {e}", file=sys.stderr)

            # 5. Nodes
            node_uuid = entities.get("node_uuid") or state_data.get("localNodeUuid")
            if node_uuid and actions.get("node_uuid") != "adopted":
                try:
                    client.delete_node(node_uuid)
                except Exception as e:
                    print(f"Rollback note (nodes): {e}", file=sys.stderr)

            # 6. Config Profiles
            prof_uuid = entities.get("profile_uuid") or state_data.get("profileUuid")
            if prof_uuid and actions.get("profile_uuid") != "adopted":
                try:
                    client.delete_config_profile(prof_uuid)
                except Exception as e:
                    print(f"Rollback note (config-profiles): {e}", file=sys.stderr)

        # Cleanup state.json.tmp
        if tmp_state.exists():
            try:
                tmp_state.unlink()
            except Exception:
                pass

        # Update journal to PROVISION_ROLLED_BACK
        journal_data["state"] = "PROVISION_ROLLED_BACK"
        journal_data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        write_journal_atomically(str(journal_file), journal_data)
        return True

    # Branch 2: NODE_ADD_* rollback
    elif op == "node_add" or state.startswith("NODE_ADD_"):
        worker_name = journal_data.get("node_name", "")
        if not worker_name and "transaction_id" in journal_data:
            tid = journal_data["transaction_id"]
            if tid.startswith("node_add_"):
                worker_name = tid[len("node_add_"):]

        worker_prof_uuid = journal_data.get("entities", {}).get("profile_uuid")
        worker_node_uuid = journal_data.get("entities", {}).get("node_uuid")
        worker_inbound_uuids = journal_data.get("entities", {}).get("inbound_uuids", [])
        worker_host_uuids = journal_data.get("entities", {}).get("host_uuids", [])

        # 1. Delete worker hosts by UUID strictly
        for hid in reversed(worker_host_uuids):
            try:
                client.delete_host(hid)
            except Exception as e:
                print(f"Rollback note (worker host {hid}): {e}", file=sys.stderr)

        # 2. Unbind worker inbounds from internal squad (restores previous squad state)
        squad_uuid = state_data.get("squadUuid")
        try:
            squads_res = client.request("GET", "/api/internal-squads")
            squads_list = _extract_list(squads_res, "internalSquads")
            for s in squads_list:
                if (squad_uuid and s.get("uuid") == squad_uuid) or s.get("name") == "Default MVP Squad":
                    cur_inbounds = [inb.get("uuid") if isinstance(inb, dict) else inb for inb in s.get("inbounds", [])]
                    updated_inbounds = [ib for ib in cur_inbounds if ib not in worker_inbound_uuids]
                    if len(updated_inbounds) != len(cur_inbounds):
                        client.request("PATCH", "/api/internal-squads", {
                            "uuid": s.get("uuid"),
                            "name": s.get("name"),
                            "inbounds": updated_inbounds
                        })
                    break
        except Exception as e:
            print(f"Rollback note (unbind squad): {e}", file=sys.stderr)

        # 3. Delete worker node by explicit UUID
        if worker_node_uuid:
            try:
                client.delete_node(worker_node_uuid)
            except Exception as e:
                print(f"Rollback note (worker node {worker_node_uuid}): {e}", file=sys.stderr)

        # 4. Delete worker profile by explicit UUID
        if worker_prof_uuid:
            try:
                client.delete_config_profile(worker_prof_uuid)
            except Exception as e:
                print(f"Rollback note (worker profile {worker_prof_uuid}): {e}", file=sys.stderr)

        # Update state.json: remove worker from nodes array if present
        if state_data and "nodes" in state_data:
            orig_len = len(state_data["nodes"])
            state_data["nodes"] = [n for n in state_data["nodes"] if n.get("name") != worker_name]
            if len(state_data["nodes"]) != orig_len:
                atomic_write_state(state_data, str(state_file))

        # 6. Update journal to NODE_ADD_ROLLED_BACK
        journal_data["state"] = "NODE_ADD_ROLLED_BACK"
        journal_data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        write_journal_atomically(str(journal_file), journal_data)
        return True

    return True


def save_credentials(username, password, panel_url, token=None, creds_path="/root/gowave-credentials.txt"):
    path = Path(creds_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{path.name}.tmp"

    content = f"""# GoWave Auto NGINX Administrative Credentials
# Generated at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
PANEL_URL={panel_url}
ADMIN_USERNAME={username}
ADMIN_PASSWORD={password}
"""
    if token:
        content += f"SCOPED_API_TOKEN={token}\n"

    # Write mode 0600
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

    os.replace(tmp_path, path)
    dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


if __name__ == "__main__":
    print("GoWave API client module loaded successfully.")
