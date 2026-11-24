#!/usr/bin/env python3
"""Suite nonroot: the install mode contract, Panel-only rendering and provisioning.

The provisioning tests execute the same heredoc the installer feeds to python3,
with a stub GoWave client on PYTHONPATH, so the call order and the state document
are observed rather than inferred from the source text.
"""
import http.server
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
GOWAVE_AUTO = REPO_ROOT / "gowave-auto.sh"
INSTALL_ARGS_SH = REPO_ROOT / "modules" / "install_args.sh"
NGINX_SH = REPO_ROOT / "modules" / "nginx.sh"
API_CLIENT = REPO_ROOT / "modules" / "api_client.py"
sys.path.insert(0, str(REPO_ROOT))

from modules.api_client import GoWaveClient  # noqa: E402

INSTALL_HEREDOC_MARKER = (
    '"$JOURNAL_FILE" "$STATE_FILE" "$CREDENTIALS_FILE" "$vision_domain" "$install_mode" '
    '3<<< "$admin_pass"'
)
NODE_ADD_HEREDOC_MARKER = (
    '"$node_port" "$admin_user" "$JOURNAL_FILE" "$STATE_FILE" "$vision_domain" '
    '3<<< "$admin_pass"'
)

STUB_CLIENT = r'''
import json
import os


def _log(name, *args):
    with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"name": name, "args": [repr(arg) for arg in args]}) + "\n")


class GoWaveNodeNameTaken(Exception):
    pass


class GoWaveClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.transaction_callback = None
        self.transaction_entities = []

    def register_initial_admin(self, username, password):
        _log("register_initial_admin", username)

    def login(self, username, password):
        _log("login", username)

    def existing_reality_material(self, *args):
        _log("existing_reality_material", *args)
        return None

    def generate_x25519(self):
        _log("generate_x25519")
        return {"privateKey": "private-stub", "publicKey": "public-stub"}

    def compile_config_profile(self, *args, **kwargs):
        _log("compile_config_profile")
        return "{}"

    def provision_config_profile(self, profile_name, raw_config):
        _log("provision_config_profile", profile_name)
        return {
            "profile_uuid": "profile-stub",
            "inbounds": [
                {"uuid": "inbound-stub-1", "tag": "vless-reality-local-node"},
                {"uuid": "inbound-stub-2", "tag": "vless-xhttp-local-node"},
            ],
        }

    def associate_node(self, *args):
        _log("associate_node", *args)
        return "node-stub"

    def list_nodes(self):
        # The registration reads the Panel's inventory before it writes; this
        # stub Panel holds no nodes, which is the state a first add meets.
        return []

    def provision_internal_squad(self, *args):
        _log("provision_internal_squad", *args)
        return os.environ.get("STUB_SQUAD", "squad-stub")

    def provision_hosts(self, profile_uuid, inbounds, node_uuid, squad_uuid, *args, **kwargs):
        _log("provision_hosts", squad_uuid)
        if kwargs.get("known_host_uuids"):
            _log("provision_hosts_known", *kwargs["known_host_uuids"])
        return ["host-stub"]

    def provision_user(self, username, squad_uuid, **kwargs):
        _log("provision_user", username, squad_uuid)
        return "short-stub"

    def attach_squad_to_user(self, username, squad_uuid):
        _log("attach_squad_to_user", username, squad_uuid)
        return os.environ.get("STUB_ATTACH", "True") != "None"

    def ensure_api_token(self, **kwargs):
        _log("ensure_api_token")
        return {"token": "token-stub"}


def atomic_write_state(state, path):
    _log("atomic_write_state", json.dumps(state, sort_keys=True))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


def save_credentials(admin_user, admin_password, panel_url, token, path):
    _log("save_credentials", admin_user, panel_url)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(f"ADMIN_USERNAME={admin_user}\nADMIN_PASSWORD={admin_password}\n")


'''

STUB_RECOVERY = r'''
import json
import os


def write_journal_atomically(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
'''


def _run_bash(script, timeout=60, env=None):
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _quote(*values):
    return " ".join(shlex.quote(str(value)) for value in values)


def _heredoc_after(marker):
    text = GOWAVE_AUTO.read_text(encoding="utf-8")
    at = text.index(marker)
    opener = text.index("<<'PY'", at) + len("<<'PY'")
    # The opener line may carry a status capture after the redirection
    # (`<<'PY' || register_rc=$?`), so the body starts after that line ends.
    start = text.index("\n", opener) + 1
    end = text.index("\nPY\n", start)
    return text[start:end]


def _prepare_stub_tree(root):
    """Write the stub modules package the extracted heredoc imports."""
    modules = root / "modules"
    modules.mkdir()
    (modules / "__init__.py").write_text("", encoding="utf-8")
    # `confirmed_country` is the shipped helper rather than a stub copy: the
    # country a node entry keeps across an unasked run is what these tests read,
    # and a second implementation here could drift from the one that runs.
    reexport = (
        "import importlib.util as _importlib_util\n"
        f"_spec = _importlib_util.spec_from_file_location('_shipped_api_client', {str(API_CLIENT)!r})\n"
        "_shipped = _importlib_util.module_from_spec(_spec)\n"
        "_spec.loader.exec_module(_shipped)\n"
        "confirmed_country = _shipped.confirmed_country\n"
    )
    (modules / "api_client.py").write_text(
        "from json import dumps as _dumps\n" + reexport + STUB_CLIENT, encoding="utf-8"
    )
    (modules / "recovery.py").write_text(STUB_RECOVERY, encoding="utf-8")


def _call_log(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestInstallArgumentContract(unittest.TestCase):
    def parse(self, *args):
        script = (
            f'source "{INSTALL_ARGS_SH}" && parse_install_arguments {_quote(*args)}; '
            "status=$?; printf 'STATUS=%s\\n' \"$status\"; "
            "printf 'MODE=%s\\n' \"${GOWAVE_INSTALL_MODE:-}\"; "
            "for value in \"${GOWAVE_INSTALL_POSITIONAL[@]:-}\"; do "
            "printf 'ARG=%s\\n' \"$value\"; done"
        )
        return _run_bash(script)

    def values(self, finished, prefix):
        return [line[len(prefix):] for line in finished.stdout.splitlines() if line.startswith(prefix)]

    def test_default_mode_is_all_in_one(self):
        finished = self.parse("panel.example.com", "cdn.example.com", "ops@example.com")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertEqual(self.values(finished, "STATUS="), ["0"])
        self.assertEqual(self.values(finished, "MODE="), ["all-in-one"])
        self.assertEqual(
            self.values(finished, "ARG="),
            ["panel.example.com", "cdn.example.com", "ops@example.com"],
        )

    def test_panel_only_flag_is_accepted_in_either_position(self):
        for args in (
            ("--panel-only", "panel.example.com", "cdn.example.com", "ops@example.com"),
            ("panel.example.com", "cdn.example.com", "ops@example.com", "--panel-only"),
            ("panel.example.com", "cdn.example.com", "--panel-only", "ops@example.com"),
        ):
            finished = self.parse(*args)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            self.assertEqual(self.values(finished, "MODE="), ["panel-only"])
            self.assertEqual(
                self.values(finished, "ARG="),
                ["panel.example.com", "cdn.example.com", "ops@example.com"],
            )

    def test_explicit_mode_spellings_are_accepted(self):
        for args, expected in (
            (("--mode", "panel-only", "p.example.com", "c.example.com", "o@example.com"), "panel-only"),
            (("--mode=all-in-one", "p.example.com", "c.example.com", "o@example.com"), "all-in-one"),
            (("--mode=panel-only", "p.example.com", "c.example.com", "o@example.com"), "panel-only"),
        ):
            finished = self.parse(*args)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            self.assertEqual(self.values(finished, "MODE="), [expected])

    def test_unknown_option_and_missing_mode_value_are_refused(self):
        for args, expected in (
            (("--bogus",), "unknown install option"),
            (("--mode",), "--mode requires"),
            (("--mode", "sideways"), "unsupported installation mode"),
        ):
            finished = self.parse(*args)
            self.assertNotEqual(finished.returncode, 0)
            self.assertIn(expected, finished.stderr)

    def test_panel_only_refuses_a_vision_domain(self):
        finished = self.parse(
            "--panel-only", "p.example.com", "c.example.com", "o@example.com", "v.example.com"
        )
        self.assertNotEqual(finished.returncode, 0)
        self.assertIn("no Vision domain", finished.stderr)


class TestPanelOnlyNginxRendering(unittest.TestCase):
    def render(self, mode, vision="", cover="", panel="panel.example.com", reality="cdn.example.com"):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "gowave-stream.conf"
            inet6 = Path(tmpdir) / "if_inet6"
            command = (
                f'source "{NGINX_SH}" && generate_stream_config {_quote(panel, reality, out, inet6, vision, cover, mode)}'
            )
            finished = _run_bash(command)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            return out.read_text(encoding="utf-8")

    def map_block(self, content):
        start = content.index("map $ssl_preread_server_name $sni_backend {")
        end = content.index("}", start) + 1
        return content[start:end]

    def test_all_in_one_map_keeps_the_traffic_backends(self):
        block = self.map_block(self.render("all-in-one", vision="vision.example.com", cover="example.com"))
        self.assertIn("panel.example.com 127.0.0.1:7443;", block)
        self.assertIn("cdn.example.com 127.0.0.1:8443;", block)
        self.assertIn("vision.example.com 127.0.0.1:8444;", block)
        self.assertIn("example.com 127.0.0.1:9443;", block)
        self.assertIn("www.example.com 127.0.0.1:9443;", block)
        self.assertIn("default 127.0.0.1:8443;", block)

    def test_panel_only_map_has_no_closed_traffic_port(self):
        content = self.render(
            "panel-only", vision="vision.example.com", cover="example.com"
        )
        block = self.map_block(content)
        self.assertIn("panel.example.com 127.0.0.1:7443;", block)
        self.assertIn("cdn.example.com 127.0.0.1:9443;", block)
        self.assertIn("example.com 127.0.0.1:9443;", block)
        self.assertIn("www.example.com 127.0.0.1:9443;", block)
        self.assertIn("default 127.0.0.1:9443;", block)
        self.assertNotIn("8443", content)
        self.assertNotIn("8444", content)

    def test_a_domain_change_keeps_the_panel_only_shape(self):
        first = self.render("panel-only", cover="example.com")
        second = self.render(
            "panel-only", panel="new-panel.example.com", reality="new-cdn.example.com", cover="example.com"
        )
        for content in (first, second):
            block = self.map_block(content)
            self.assertNotIn("8443", block)
            self.assertNotIn("8444", block)
            self.assertIn("default 127.0.0.1:9443;", block)
        self.assertEqual(first.count("\n"), second.count("\n"))

    def test_decoy_vhost_uses_the_camouflage_lineage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "gowave-decoy.conf"
            cover = Path(tmpdir) / "cover-reality"
            command = (
                f'source "{NGINX_SH}" && generate_decoy_vhost '
                f'{_quote("cdn.example.com", out, "nginx", cover, "example.com")}'
            )
            finished = _run_bash(command)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            content = out.read_text(encoding="utf-8")
            self.assertIn("ssl_certificate /etc/letsencrypt/live/cdn.example.com/fullchain.pem;", content)
            self.assertIn("ssl_certificate_key /etc/letsencrypt/live/cdn.example.com/privkey.pem;", content)


class TestInstallSourceContract(unittest.TestCase):
    def test_panel_only_skips_the_vision_fallback_and_the_local_node(self):
        text = GOWAVE_AUTO.read_text(encoding="utf-8")
        self.assertRegex(
            text,
            r'if \[\[ "\$install_mode" == "all-in-one" && -n "\$vision_domain" \]\]; then\s*\n\s*generate_vision_fallback_vhost',
        )
        self.assertRegex(
            text,
            r'if \[\[ "\$install_mode" == "all-in-one" \]\]; then\s*\n\s*local secret_key',
        )

    def test_node_add_takes_the_squad_from_the_call_that_provides_it(self):
        body = _heredoc_after(NODE_ADD_HEREDOC_MARKER)
        self.assertIn('squad_uuid = client.provision_internal_squad(', body)
        self.assertNotIn('state_data.get("squadUuid")', body)
        self.assertLess(
            body.index("squad_uuid = client.provision_internal_squad("),
            body.index("client.provision_hosts("),
        )

    def test_domain_change_reads_the_recorded_mode(self):
        text = GOWAVE_AUTO.read_text(encoding="utf-8")
        self.assertIn("install_mode=$(installation_mode_from_state)", text)
        self.assertRegex(
            text,
            r'generate_stream_config "\$new_panel_domain" .*"\$cover_domain" "\$install_mode"',
        )


class TestInstallProvisioning(unittest.TestCase):
    def run_install_heredoc(self, mode, vision=""):
        body = _heredoc_after(INSTALL_HEREDOC_MARKER)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            script_dir = root / "stub-src"
            script_dir.mkdir()
            _prepare_stub_tree(script_dir)
            script = root / "install_provision.py"
            script.write_text(body, encoding="utf-8")
            state = root / "state.json"
            journal = root / "journal.json"
            credentials = root / "credentials.txt"
            log = root / "calls.jsonl"
            command = (
                f'CALL_LOG={shlex.quote(str(log))} python3 {shlex.quote(str(script))} '
                f'{_quote(script_dir, "panel.example.com", "cdn.example.com", "admin", journal, state, credentials, vision, mode)} '
                f"3<<<'admin-password'"
            )
            finished = _run_bash(command)
            return (
                finished,
                _call_log(log),
                state.read_text(encoding="utf-8") if state.exists() else None,
                credentials.exists(),
            )

    def test_all_in_one_provisions_the_local_node_in_order(self):
        finished, calls, state, _credentials = self.run_install_heredoc("all-in-one")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        names = [call["name"] for call in calls]
        expected = [
            "register_initial_admin",
            "login",
            "existing_reality_material",
            "generate_x25519",
            "compile_config_profile",
            "provision_config_profile",
            "associate_node",
            "provision_internal_squad",
            "provision_hosts",
            "provision_user",
            "ensure_api_token",
            "save_credentials",
            "atomic_write_state",
        ]
        self.assertEqual(names, expected)
        document = json.loads(state)
        self.assertEqual(document["installationMode"], "all-in-one")
        self.assertEqual(document["schemaVersion"], 2)
        self.assertEqual(document["squadUuid"], "squad-stub")
        self.assertEqual([node["name"] for node in document["nodes"]], ["local-node"])

    def test_the_state_records_the_hosts_the_run_owns(self):
        finished, calls, state, _credentials = self.run_install_heredoc("all-in-one")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        document = json.loads(state)
        self.assertEqual(document["nodes"][0]["hostUuids"], ["host-stub"])
        self.assertEqual(
            [call["name"] for call in calls if call["name"] == "provision_hosts_known"],
            [],
            "a first install has no recorded Hosts to reconcile",
        )

    def test_panel_only_stops_after_admin_token_and_default_user(self):
        finished, calls, state, credentials = self.run_install_heredoc("panel-only")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        names = [call["name"] for call in calls]
        self.assertEqual(
            names,
            ["register_initial_admin", "login", "provision_user", "ensure_api_token",
             "save_credentials", "atomic_write_state"],
        )
        user_call = next(call for call in calls if call["name"] == "provision_user")
        self.assertEqual(user_call["args"], ["'default-user'", "None"])
        document = json.loads(state)
        self.assertEqual(document["installationMode"], "panel-only")
        self.assertEqual(document["schemaVersion"], 2)
        self.assertEqual(document["panelDomain"], "panel.example.com")
        self.assertEqual(document["realityDomain"], "cdn.example.com")
        self.assertEqual(document["nodes"], [])
        for absent in ("localNodeUuid", "nodePort", "profileUuid", "squadUuid"):
            self.assertNotIn(absent, document)
        self.assertTrue(credentials)


class TestNodeSquadProvisioning(unittest.TestCase):
    def run_node_add(self, state_document, squad):
        body = _heredoc_after(NODE_ADD_HEREDOC_MARKER)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            script_dir = root / "stub-src"
            script_dir.mkdir()
            _prepare_stub_tree(script_dir)
            script = root / "node_add.py"
            script.write_text(body, encoding="utf-8")
            state = root / "state.json"
            state.write_text(json.dumps(state_document), encoding="utf-8")
            journal = root / "journal.json"
            log = root / "calls.jsonl"
            command = (
                f'CALL_LOG={shlex.quote(str(log))} STUB_SQUAD={shlex.quote(squad)} '
                f'python3 {shlex.quote(str(script))} '
                f'{_quote(script_dir, "worker-1", "203.0.113.10", "w1.example.com", "w1-cdn.example.com", "3002", "admin", journal, state, "")} '
                f"3<<<'admin-password'"
            )
            finished = _run_bash(command)
            return finished, _call_log(log), state.read_text(encoding="utf-8")

    def test_the_first_worker_after_a_panel_only_install_carries_the_new_squad(self):
        finished, calls, state = self.run_node_add(
            {"schemaVersion": 2, "installationMode": "panel-only", "nodes": []}, "squad-new"
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        host_calls = [call for call in calls if call["name"] == "provision_hosts"]
        self.assertEqual(len(host_calls), 1)
        self.assertEqual(host_calls[0]["args"], ["'squad-new'"])
        self.assertNotIn("None", host_calls[0]["args"])
        document = json.loads(state)
        self.assertEqual(document["squadUuid"], "squad-new")
        self.assertEqual(document["nodes"][0]["name"], "worker-1")

    def test_an_empty_squad_aborts_before_the_host_record(self):
        original = {"schemaVersion": 2, "installationMode": "panel-only", "nodes": []}
        finished, calls, state = self.run_node_add(original, "")
        self.assertNotEqual(finished.returncode, 0)
        self.assertIn("no internal squad identifier", finished.stderr)
        self.assertEqual([call["name"] for call in calls if call["name"] == "provision_hosts"], [])
        self.assertEqual(json.loads(state), original)

    def test_the_default_user_joins_the_squad_before_the_host_records(self):
        # Measured on the live pair: a Panel-only install creates default-user with
        # no squad, and the Panel answered that user's subscription with its own
        # "No Hosts Available" placeholder until the user was assigned the squad.
        finished, calls, _ = self.run_node_add(
            {"schemaVersion": 2, "installationMode": "panel-only", "nodes": []}, "squad-new"
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        order = [call["name"] for call in calls]
        attach = [call for call in calls if call["name"] == "attach_squad_to_user"]
        self.assertEqual(len(attach), 1, order)
        self.assertEqual(attach[0]["args"], ["'default-user'", "'squad-new'"])
        self.assertLess(order.index("provision_internal_squad"), order.index("attach_squad_to_user"))
        self.assertLess(order.index("attach_squad_to_user"), order.index("provision_hosts"))

    def test_a_retry_reconciles_the_hosts_and_the_country_it_recorded(self):
        recorded = {
            "schemaVersion": 2,
            "installationMode": "all-in-one",
            "nodes": [{
                "name": "worker-1",
                "address": "203.0.113.10",
                "port": 3002,
                "uuid": "node-1",
                "country": "DE",
                "hostUuids": ["host-old"],
            }],
        }
        finished, calls, state = self.run_node_add(recorded, "squad-new")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        known = [call for call in calls if call["name"] == "provision_hosts_known"]
        self.assertEqual([call["args"] for call in known], [["'host-old'"]])
        entry = json.loads(state)["nodes"][0]
        self.assertEqual(len(json.loads(state)["nodes"]), 1, "a retry updates its record, it does not add one")
        self.assertEqual(entry["hostUuids"], ["host-stub"])
        self.assertEqual(entry["country"], "DE", "a run that asked nothing keeps the confirmed country")

    def test_an_already_assigned_user_does_not_stop_the_worker(self):
        # An All-in-One node add finds the user already holding the squad, so the
        # attach reports False and stops nothing; a Panel without that user reports
        # None, which is the same answer as "nothing to attach".
        for stub in ("False", "None"):
            with self.subTest(stub=stub):
                with mock.patch.dict(os.environ, {"STUB_ATTACH": stub}):
                    finished, calls, state = self.run_node_add(
                        {"schemaVersion": 2, "installationMode": "all-in-one", "nodes": []},
                        "squad-existing",
                    )
                self.assertEqual(finished.returncode, 0, finished.stderr)
                self.assertEqual(
                    [call["name"] for call in calls].count("provision_hosts"), 1
                )
                self.assertEqual(json.loads(state)["nodes"][0]["name"], "worker-1")


class _SquadHandler(http.server.BaseHTTPRequestHandler):
    posts = []
    squads = {}

    def log_message(self, format, *args):
        pass

    def send_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/internal-squads":
            self.send_json({"response": {"internalSquads": list(self.squads.values())}})
        else:
            self.send_json({"response": {}})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        if self.path == "/api/internal-squads" and body.get("uuid") in self.squads:
            self.squads[body["uuid"]].update(body)
        self.send_json({"response": {"status": "updated"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        type(self).posts.append(self.path)
        uuid = f"squad-{len(self.squads) + 1}"
        type(self).squads[uuid] = {"uuid": uuid, **body}
        self.send_json({"response": {"uuid": uuid, "name": body.get("name")}})


class TestSquadReuse(unittest.TestCase):
    def test_the_second_worker_reuses_the_squad_without_a_duplicate_post(self):
        _SquadHandler.posts = []
        _SquadHandler.squads = {}
        server = http.server.HTTPServer(("127.0.0.1", 0), _SquadHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            client = GoWaveClient(f"http://127.0.0.1:{server.server_address[1]}")
            first = client.provision_internal_squad("Default MVP Squad", ["inbound-1"])
            second = client.provision_internal_squad("Default MVP Squad", ["inbound-2"])
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(first, second)
        self.assertEqual(_SquadHandler.posts, ["/api/internal-squads"])
        inbounds = _SquadHandler.squads[first]["inbounds"]
        self.assertEqual(inbounds, ["inbound-1", "inbound-2"])


class TestPanelOnlyHealthAndStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "systemctl").write_text(
            "#!/usr/bin/env bash\necho inactive\nexit 1\n", encoding="utf-8"
        )
        (self.bin / "ss").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (self.bin / "curl").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        for command in self.bin.iterdir():
            command.chmod(0o755)
        self.state = self.root / "state.json"
        self.state.write_text(
            json.dumps({
                "schemaVersion": 2,
                "installationMode": "panel-only",
                "panelDomain": "panel.example.com",
                "realityDomain": "cdn.example.com",
                "nodes": [],
            }),
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def run_command(self, verb):
        return subprocess.run(
            ["bash", str(GOWAVE_AUTO), verb],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "GOWAVE_STATE_FILE": str(self.state),
            },
        )

    def test_health_is_healthy_without_a_local_node(self):
        finished = self.run_command("health")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertIn("intentionally absent in Panel-only mode", finished.stderr)
        self.assertIn("Overall health status: HEALTHY", finished.stdout)

    def test_status_names_the_absent_node_and_free_ports(self):
        finished = self.run_command("status")
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertRegex(finished.stdout, r"gowave-node\.service\s+: not present \(panel-only installation\)")
        for port in ("3002", "8443", "8444"):
            self.assertRegex(finished.stdout, rf"Port {port}\s+: FREE")


if __name__ == "__main__":
    unittest.main()
