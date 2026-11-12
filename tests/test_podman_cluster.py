#!/usr/bin/env python3
"""Suite nonroot: the cluster audit proves relations, not totals.

CLUS-01..03 run against the real Panel of a two-node install, so what a unit
test can hold is the part the live run relies on being right: the probe must
report every relation as a digest (never an identifier), and each case must
refuse the defect it exists to catch instead of accepting a plausible total.
"""
import io
import json
import sys
import tempfile
import threading
import types
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import (  # noqa: E402
    acme_fixture, matrix, multi_node, panel_surface, topology,
)

PASSWORD = "pw-do-not-print"
TOKEN = "token-do-not-print"
PRIVATE_KEY_SENTINEL = "reality-private-key-do-not-print"

MASTER_NODE_UUID = "node-uuid-master"
WORKER_NODE_UUID = "node-uuid-worker"
MASTER_PROFILE_UUID = "profile-uuid-master"
WORKER_PROFILE_UUID = "profile-uuid-worker"
OUTBOUNDS = ("direct", "block", "dns-out", "freedom", "blackhole")


def inbound_uuids(node: str, vision: bool):
    """One inbound UUID per matrix entry the node's profile carries."""
    entries = matrix.inbounds(matrix.load(), vision=vision)
    return [f"inbound-uuid-{node}-{index}" for index, _entry in enumerate(entries)]


def inbound_specs(node: str, vision: bool):
    """One declared inbound per matrix entry, in the Panel's own field names.

    The values come from the shipped templates because that is what the Panel
    parses into an inbound row, so a fixture cannot drift from the product.
    """
    specs = []
    for entry in matrix.inbounds(matrix.load(), vision=vision):
        template = json.loads((REPO_ROOT / entry["template"]).read_text(encoding="utf-8"))
        stream = template.get("streamSettings") or {}
        specs.append({
            "tag": f"{entry['tag']}-{node}",
            "type": template.get("protocol"),
            "port": template.get("port"),
            "network": stream.get("network"),
            "security": stream.get("security"),
        })
    return specs


NODE_VERSIONS = {
    "node": "v1.0.5 (Go)",
    "xray": "v26.11.9",
    "node_type": "go",
    "custom_core": False,
}

NODE_STATE = {
    "disabled": False,
    "connecting": False,
    "status_message": "",
    "last_status_change": "2026-11-12T17:00:00Z",
}


def host_record(node_name, node_uuid, profile_uuid, inbound_uuid, address,
                security_layer, fingerprint="firefox", nodes=None):
    return {
        "remark": f"{security_layer}-host@{node_name}",
        "address": address,
        "port": 443,
        "sni": address,
        "fingerprint": fingerprint,
        "security_layer": security_layer,
        "disabled": False,
        "profile": panel_surface.identifier(profile_uuid),
        "inbound": panel_surface.identifier(inbound_uuid),
        "nodes": [panel_surface.identifier(node_uuid)] if nodes is None else nodes,
    }


def healthy_cluster(vision=False, worker_vision=False):
    """The facts a healthy two-node install produces, in the probe's own shape."""
    master = inbound_uuids("master", vision)
    worker = inbound_uuids("worker", worker_vision)
    nodes = [
        {
            "name": multi_node.LOCAL_NODE_NAME,
            "address": "127.0.0.1",
            "port": multi_node.NODE_PORT,
            "connected": True,
            "uuid": panel_surface.identifier(MASTER_NODE_UUID),
            "profile": panel_surface.identifier(MASTER_PROFILE_UUID),
            "inbounds": [panel_surface.identifier(value) for value in master],
            "inbound_specs": inbound_specs("master", vision),
            "state": dict(NODE_STATE),
            "versions": dict(NODE_VERSIONS),
        },
        {
            "name": topology.WORKER_NODE_NAME,
            "address": topology.allocate_plan([]).worker_ip,
            "port": multi_node.NODE_PORT,
            "connected": True,
            "uuid": panel_surface.identifier(WORKER_NODE_UUID),
            "profile": panel_surface.identifier(WORKER_PROFILE_UUID),
            "inbounds": [panel_surface.identifier(value) for value in worker],
            "inbound_specs": inbound_specs("worker", worker_vision),
            "state": dict(NODE_STATE),
            "versions": dict(NODE_VERSIONS),
        },
    ]
    profiles = [
        {
            "name": f"GoWave MVP Unified Profile - {multi_node.LOCAL_NODE_NAME}",
            "uuid": panel_surface.identifier(MASTER_PROFILE_UUID),
            "inbounds": [panel_surface.identifier(value) for value in master],
            "computed": {"status": 200, "parsed": True,
                         "inbound_count": len(master), "outbound_count": len(OUTBOUNDS)},
        },
        {
            "name": f"GoWave Worker {topology.WORKER_NODE_NAME} Profile",
            "uuid": panel_surface.identifier(WORKER_PROFILE_UUID),
            "inbounds": [panel_surface.identifier(value) for value in worker],
            "computed": {"status": 200, "parsed": True,
                         "inbound_count": len(worker), "outbound_count": len(OUTBOUNDS)},
        },
    ]
    hosts = []
    for index, inbound in enumerate(master):
        # The Master's optional Vision inbound is published under the Master's
        # Vision domain; every other Master host is dialled on the Panel domain.
        vision_host = vision and index == len(master) - 1
        hosts.append(host_record(
            multi_node.LOCAL_NODE_NAME, MASTER_NODE_UUID, MASTER_PROFILE_UUID, inbound,
            topology.VISION_DOMAIN if vision_host else topology.PANEL_DOMAIN,
            "DEFAULT" if index == 0 else "TLS",
        ))
    for index, inbound in enumerate(worker):
        # The optional Vision inbound is published under the Worker's Vision
        # domain; every other Worker host is dialled on the Worker's VPN domain.
        vision_host = worker_vision and index == len(worker) - 1
        hosts.append(host_record(
            topology.WORKER_NODE_NAME, WORKER_NODE_UUID, WORKER_PROFILE_UUID, inbound,
            topology.WORKER_VISION_DOMAIN if vision_host else topology.WORKER_DOMAIN,
            "DEFAULT" if index == 0 else "TLS",
        ))
    return {
        "nodes": {"status": 200, "records": nodes},
        "profiles": {"status": 200, "records": profiles},
        "hosts": {"status": 200, "records": hosts},
        "squad": {
            "status": 200,
            "name": "Default MVP Squad",
            "mvp_present": True,
            "inbounds": [panel_surface.identifier(value) for value in master + worker],
        },
    }


def topology_fixture(vision=False, worker_vision=False):
    """The topology attributes the cases read: the plan and the Worker's domains."""
    return types.SimpleNamespace(
        plan=topology.allocate_plan([]),
        panel_domain=topology.PANEL_DOMAIN,
        worker_domain=topology.WORKER_DOMAIN,
        worker_vision_domain=topology.WORKER_VISION_DOMAIN if worker_vision else None,
    )


class _ClusterProduct(multi_node.MultiNodeProduct):
    """The installed product, with the Panel probe replaced by prepared facts."""

    def __init__(self, cluster, vision=False, worker_vision=False):
        self.podman = None
        self.vision = vision
        self.worker_vision = worker_vision
        self.matrix = matrix.load()
        self.topology = topology_fixture(vision, worker_vision)
        self.node_add_outcome = types.SimpleNamespace(ok=True)
        self.master = types.SimpleNamespace(require_installed=lambda: None)
        self.cluster = cluster

    def panel_cluster(self, case_id):
        return {"login": {"status": 200}, "cluster": self.cluster}


def applied_inbounds(vision: bool):
    """The inbounds a node's own applied config carries, in the probe's shape."""
    inbounds = []
    for entry in matrix.inbounds(matrix.load(), vision=vision):
        template = json.loads((REPO_ROOT / entry["template"]).read_text(encoding="utf-8"))
        stream = template.get("streamSettings") or {}
        inbounds.append({
            "tag": f"{entry['tag']}-node",
            "type": template.get("protocol"),
            "port": template.get("port"),
            "listen": str(template.get("listen") or ""),
            "network": stream.get("network") or "tcp",
            "security": stream.get("security") or "none",
        })
    return inbounds


def vision_node_facts(domain, vision):
    """What one node's own probe reports for the Vision name it was asked about."""
    port = multi_node.vision_identity(matrix.load())["port"]
    facts = {
        "domain": domain,
        "port": port,
        "certificate": {
            "lineage": f"/etc/letsencrypt/live/{domain}",
            "present": False,
            "host_ok": False,
            "valid": False,
            "issuer": "",
            "renewal_server": "",
        },
        "nginx": {
            "stream_routes": [],
            "stream_vision_targets": [],
            "vhost_files": [],
            "vision_named_files": [],
        },
        "applied": {"parsed": True, "inbounds": applied_inbounds(vision)},
    }
    if vision:
        facts["certificate"] = {
            "lineage": f"/etc/letsencrypt/live/{domain}",
            "present": True,
            "host_ok": True,
            "valid": True,
            "issuer": "issuer=CN = Pebble Intermediate CA",
            "renewal_server": acme_fixture.ACME_DIRECTORY_URL,
        }
        facts["nginx"] = {
            "stream_routes": [
                {"file": "gowave-stream.conf", "target": f"127.0.0.1:{port};"},
            ],
            "stream_vision_targets": ["gowave-stream.conf"],
            "vhost_files": ["gowave-vision-fallback.conf"],
            "vision_named_files": ["gowave-vision-fallback.conf"],
        }
    return facts


def cluster_node_facts(vision, worker_vision):
    return {
        "master": vision_node_facts(topology.VISION_DOMAIN, vision),
        "worker": vision_node_facts(topology.WORKER_VISION_DOMAIN, worker_vision),
    }


class _VisionProduct(_ClusterProduct):
    """The installed product with the per-node filesystem probe replaced.

    The probe reads inside a node's container, so the test supplies what each
    node would report and records which node was asked about which name.
    """

    def __init__(self, cluster, node_facts, vision=False, worker_vision=False):
        super().__init__(cluster, vision=vision, worker_vision=worker_vision)
        self.node_facts = node_facts
        self.vision_probes = []

    def require_worker(self):
        return self.topology

    def node_vision_facts(self, case_id, node, domain, port):
        self.vision_probes.append((node, domain, port))
        return self.node_facts[node]


class TestClusterScope(unittest.TestCase):
    """The probe reports the relations as digests, and never an identifier."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.credentials = Path(self.tmp.name) / "credentials"
        self.credentials.write_text(
            f"ADMIN_USERNAME=admin\nADMIN_PASSWORD={PASSWORD}\n", encoding="utf-8"
        )
        self.credentials.chmod(0o600)
        self.cluster = healthy_cluster()
        self.requests = []
        self.server = self._start_stub()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def _start_stub(self):
        cluster = self.cluster
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body):
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/api/auth/login" and body.get("password") == PASSWORD:
                    return self._send(200, {"response": {"accessToken": TOKEN}})
                return self._send(401, {"error": "Unauthorized"})

            def do_GET(self):
                requests.append((self.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"error": "Unauthorized"})
                if self.path == "/api/nodes":
                    return self._send(200, {"response": self.server.nodes})
                if self.path == "/api/config-profiles":
                    return self._send(200, {"response": {"configProfiles": self.server.profiles}})
                if self.path.startswith("/api/config-profiles/"):
                    uuid = self.path.split("/")[3]
                    profile = next(
                        (item for item in self.server.profiles if item.get("uuid") == uuid), None
                    )
                    if profile is None:
                        return self._send(404, {"message": "Config profile not found"})
                    return self._send(200, {"response": {
                        "uuid": uuid,
                        "config": {
                            "log": {"loglevel": "warning"},
                            "inbounds": [{"tag": f"inbound-{index}"}
                                         for index in range(len(profile["inbounds"]))],
                            "outbounds": [{"protocol": "freedom", "tag": tag}
                                          for tag in OUTBOUNDS],
                        },
                    }})
                if self.path == "/api/internal-squads":
                    return self._send(200, {"response": {"internalSquads": [self.server.squad]}})
                if self.path == "/api/hosts":
                    return self._send(200, {"response": self.server.hosts})
                return self._send(404, {"message": "not found"})

        def wire(payload):
            """Rehydrate the prepared facts into the Panel's real payload shapes."""

            def raw(value):
                return reverse.get(value, value)

            # The Panel stores the inbound template verbatim with its keys, so a
            # probe that echoed it would leak the REALITY secret.
            raw_inbound = json.dumps({"privateKey": PRIVATE_KEY_SENTINEL})

            server_payload = {
                "nodes": [
                    {
                        "uuid": raw(record["uuid"]),
                        "name": record["name"],
                        "address": record["address"],
                        "port": record["port"],
                        "isConnected": record["connected"],
                        "isDisabled": record["state"]["disabled"],
                        "isConnecting": record["state"]["connecting"],
                        "lastStatusMessage": record["state"]["status_message"] or None,
                        "lastStatusChange": record["state"]["last_status_change"],
                        "versions": {
                            "node": record["versions"]["node"],
                            "xray": record["versions"]["xray"],
                            "nodeType": record["versions"]["node_type"],
                            "isCustom": record["versions"]["custom_core"],
                        },
                        "configProfile": {
                            "activeConfigProfileUuid": raw(record["profile"]),
                            "activeInbounds": [
                                dict(spec, uuid=raw(value), rawInbound=raw_inbound)
                                for value, spec in zip(
                                    record["inbounds"], record["inbound_specs"]
                                )
                            ],
                        },
                    }
                    for record in payload["nodes"]["records"]
                ],
                "profiles": [
                    {
                        "uuid": raw(record["uuid"]),
                        "name": record["name"],
                        "inbounds": [
                            {"uuid": raw(value), "tag": f"tag-{index}", "type": "vless"}
                            for index, value in enumerate(record["inbounds"])
                        ],
                    }
                    for record in payload["profiles"]["records"]
                ],
                "hosts": [
                    {
                        "uuid": f"host-uuid-{index}",
                        "remark": record["remark"],
                        "address": record["address"],
                        "port": record["port"],
                        "sni": record["sni"],
                        "fingerprint": record["fingerprint"],
                        "securityLayer": record["security_layer"],
                        "isDisabled": record["disabled"],
                        "inbound": {
                            "configProfileUuid": raw(record["profile"]),
                            "configProfileInboundUuid": raw(record["inbound"]),
                        },
                        "nodes": [raw(value) for value in record["nodes"]],
                    }
                    for index, record in enumerate(payload["hosts"]["records"])
                ],
                "squad": {
                    "uuid": "squad-uuid",
                    "name": payload["squad"]["name"],
                    "inbounds": [
                        {"uuid": raw(value)} for value in payload["squad"]["inbounds"]
                    ],
                },
            }
            return server_payload

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        reverse = {
            panel_surface.identifier(MASTER_NODE_UUID): MASTER_NODE_UUID,
            panel_surface.identifier(WORKER_NODE_UUID): WORKER_NODE_UUID,
            panel_surface.identifier(MASTER_PROFILE_UUID): MASTER_PROFILE_UUID,
            panel_surface.identifier(WORKER_PROFILE_UUID): WORKER_PROFILE_UUID,
        }
        for node in ("master", "worker"):
            for index in range(6):
                value = f"inbound-uuid-{node}-{index}"
                reverse[panel_surface.identifier(value)] = value
        wired = wire(self.cluster)
        server.nodes = wired["nodes"]
        server.profiles = wired["profiles"]
        server.hosts = wired["hosts"]
        server.squad = wired["squad"]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.port = server.server_address[1]
        return server

    def _probe(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = panel_surface.main([
                "--scope", "cluster",
                "--panel-url", f"http://127.0.0.1:{self.port}",
                "--credentials", str(self.credentials),
            ])
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertNotIn(PASSWORD, output)
        self.assertNotIn(TOKEN, output)
        return json.loads(output), output

    def test_the_probe_reports_each_node_with_its_own_profile_and_inbounds(self):
        facts, _output = self._probe()
        records = {record["name"]: record for record in facts["cluster"]["nodes"]["records"]}
        self.assertEqual(sorted(records), [multi_node.LOCAL_NODE_NAME, topology.WORKER_NODE_NAME])
        for name, count in ((multi_node.LOCAL_NODE_NAME, 4), (topology.WORKER_NODE_NAME, 4)):
            self.assertEqual(len(records[name]["inbounds"]), count)
            self.assertTrue(records[name]["profile"])
        worker = records[topology.WORKER_NODE_NAME]
        self.assertEqual(worker["address"], self.cluster["nodes"]["records"][1]["address"])

    def test_every_host_keeps_its_node_inbound_and_fingerprint_relation(self):
        facts, _output = self._probe()
        hosts = facts["cluster"]["hosts"]["records"]
        self.assertEqual(len(hosts), 8)
        for record in hosts:
            self.assertEqual(len(record["nodes"]), 1)
            self.assertTrue(record["inbound"])
            self.assertTrue(record["profile"])
            self.assertEqual(record["fingerprint"], "firefox")
        self.assertEqual(sorted({record["security_layer"] for record in hosts}), ["DEFAULT", "TLS"])

    def test_the_computed_config_is_read_per_profile_and_reduced_to_its_shape(self):
        facts, _output = self._probe()
        for profile in facts["cluster"]["profiles"]["records"]:
            computed = profile["computed"]
            self.assertEqual(computed["status"], 200)
            self.assertIs(computed["parsed"], True)
            self.assertEqual(computed["inbound_count"], len(profile["inbounds"]))
            self.assertEqual(computed["outbound_count"], len(OUTBOUNDS))
        paths = [path for path, _auth in self.requests if "computed-config" in path]
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(auth == f"Bearer {TOKEN}" for path, auth in self.requests),
                        "every cluster read must carry the admin token")

    def test_the_squad_grants_every_inbound_the_nodes_run(self):
        facts, _output = self._probe()
        granted = facts["cluster"]["squad"]["inbounds"]
        nodes = facts["cluster"]["nodes"]["records"]
        self.assertEqual(sorted(granted),
                         sorted({value for node in nodes for value in node["inbounds"]}))
        self.assertEqual(len(granted), 8)

    def test_the_report_carries_no_internal_identifier(self):
        _facts, output = self._probe()
        for value in (MASTER_NODE_UUID, WORKER_NODE_UUID, MASTER_PROFILE_UUID,
                      WORKER_PROFILE_UUID, "inbound-uuid-master-0", "inbound-uuid-worker-3",
                      PRIVATE_KEY_SENTINEL):
            self.assertNotIn(value, output, f"the report leaked {value!r}")

    def test_each_node_reports_the_inbounds_it_declares(self):
        facts, _output = self._probe()
        records = {record["name"]: record for record in facts["cluster"]["nodes"]["records"]}
        for name, specs in (
            (multi_node.LOCAL_NODE_NAME, inbound_specs("master", False)),
            (topology.WORKER_NODE_NAME, inbound_specs("worker", False)),
        ):
            reported = records[name]["inbound_specs"]
            self.assertEqual(len(reported), 4)
            self.assertEqual(reported, specs)
            self.assertEqual(sorted(reported[0]),
                             ["network", "port", "security", "tag", "type"])

    def test_each_node_reports_its_own_state_and_versions(self):
        facts, _output = self._probe()
        records = {record["name"]: record for record in facts["cluster"]["nodes"]["records"]}
        for record in records.values():
            self.assertEqual(record["state"], NODE_STATE)
            self.assertEqual(record["versions"], NODE_VERSIONS)
        self.assertIs(records[topology.WORKER_NODE_NAME]["state"]["disabled"], False)


class TestClusterCases(unittest.TestCase):
    """CLUS-01..03: each case refuses the structure defect it owns."""

    def _run(self, case, cluster=None, **flags):
        product = _ClusterProduct(cluster or healthy_cluster(**flags), **flags)
        return case(product)

    def test_the_healthy_cluster_satisfies_all_three_cases(self):
        hosts = self._run(multi_node.case_cluster_hosts)
        self.assertEqual(hosts["host_count"], 8)
        self.assertEqual(hosts["hosts_per_node"],
                         {multi_node.LOCAL_NODE_NAME: 4, topology.WORKER_NODE_NAME: 4})
        squad = self._run(multi_node.case_cluster_squad)
        self.assertEqual(squad["granted_inbound_count"], 8)
        nodes = self._run(multi_node.case_cluster_nodes)
        self.assertEqual(nodes["profile_count"], 2)
        self.assertEqual(nodes["worker_host_count"], 4)

    def test_both_nodes_running_vision_raise_the_expected_counts(self):
        hosts = self._run(multi_node.case_cluster_hosts, vision=True, worker_vision=True)
        self.assertEqual(hosts["host_count"], 10)
        squad = self._run(multi_node.case_cluster_squad, vision=True, worker_vision=True)
        self.assertEqual(squad["granted_inbound_count"], 10)
        nodes = self._run(multi_node.case_cluster_nodes, vision=True, worker_vision=True)
        self.assertEqual(nodes["inbounds_per_node"],
                         {multi_node.LOCAL_NODE_NAME: 5, topology.WORKER_NODE_NAME: 5})

    # ------------------------------------------------------------- CLUS-01
    def test_a_host_total_that_does_not_match_the_configuration_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"].pop()
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("expected 8", str(caught.exception))

    def test_a_host_referencing_two_nodes_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"][0]["nodes"].append(
            panel_surface.identifier(WORKER_NODE_UUID)
        )
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("instead of exactly one", str(caught.exception))

    def test_a_host_referencing_an_unlisted_node_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"][0]["nodes"] = [panel_surface.identifier("node-unknown")]
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("does not list", str(caught.exception))

    def test_a_host_publishing_another_nodes_inbound_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"][4]["inbound"] = cluster["nodes"]["records"][0]["inbounds"][0]
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("not among the inbounds", str(caught.exception))

    def test_a_host_on_a_profile_its_node_does_not_run_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"][0]["profile"] = panel_surface.identifier(WORKER_PROFILE_UUID)
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("belongs to a profile", str(caught.exception))

    def test_a_host_count_that_is_lopsided_between_nodes_is_refused(self):
        cluster = healthy_cluster()
        duplicate = dict(cluster["hosts"]["records"][0])
        duplicate["remark"] = "duplicate-host@local-node"
        cluster["hosts"]["records"][4] = duplicate
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("expected one per active inbound", str(caught.exception))

    def test_a_host_without_the_pinned_fingerprint_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"][2]["fingerprint"] = "chrome"
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("pinned", str(caught.exception))

    def test_hosts_that_never_exercise_both_security_layers_are_refused(self):
        cluster = healthy_cluster()
        for record in cluster["hosts"]["records"]:
            record["security_layer"] = "TLS"
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_hosts, cluster)
        self.assertIn("security layers", str(caught.exception))

    # ------------------------------------------------------------- CLUS-02
    def test_a_missing_squad_is_refused(self):
        cluster = healthy_cluster()
        cluster["squad"]["mvp_present"] = False
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_squad, cluster)
        self.assertIn("lists no", str(caught.exception))

    def test_a_squad_with_a_duplicate_inbound_is_refused(self):
        cluster = healthy_cluster()
        cluster["squad"]["inbounds"].append(cluster["squad"]["inbounds"][0])
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_squad, cluster)
        self.assertIn("more than once", str(caught.exception))

    def test_a_squad_missing_an_inbound_is_refused(self):
        cluster = healthy_cluster()
        dropped = cluster["squad"]["inbounds"].pop()
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_squad, cluster)
        message = str(caught.exception)
        self.assertIn("differs from the inbounds", message)
        self.assertIn(dropped, message)

    def test_a_squad_granting_an_unrelated_inbound_is_refused(self):
        cluster = healthy_cluster()
        cluster["squad"]["inbounds"][0] = panel_surface.identifier("inbound-uuid-stray")
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_squad, cluster)
        self.assertIn("extra", str(caught.exception))

    # ------------------------------------------------------------- CLUS-03
    def test_a_single_node_is_refused(self):
        cluster = healthy_cluster()
        cluster["nodes"]["records"].pop()
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("instead of the Master and the Worker", str(caught.exception))

    def test_the_wrong_master_address_is_refused(self):
        cluster = healthy_cluster()
        cluster["nodes"]["records"][0]["address"] = "10.89.0.99"
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("is registered at", str(caught.exception))

    def test_the_wrong_worker_node_api_address_is_refused(self):
        cluster = healthy_cluster()
        cluster["nodes"]["records"][1]["address"] = topology.PANEL_DOMAIN
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("Node API address", str(caught.exception))

    def test_a_node_with_the_wrong_inbound_count_is_refused(self):
        cluster = healthy_cluster()
        cluster["nodes"]["records"][1]["inbounds"].pop()
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("active inbounds", str(caught.exception))

    def test_an_inbound_shared_by_both_nodes_is_refused(self):
        cluster = healthy_cluster()
        shared = cluster["nodes"]["records"][0]["inbounds"][0]
        cluster["nodes"]["records"][1]["inbounds"][0] = shared
        cluster["profiles"]["records"][1]["inbounds"][0] = shared
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("share an inbound UUID", str(caught.exception))

    def test_a_profile_that_declares_other_inbounds_than_the_node_runs_is_refused(self):
        cluster = healthy_cluster()
        cluster["profiles"]["records"][1]["inbounds"].pop()
        cluster["profiles"]["records"][1]["computed"]["inbound_count"] = 3
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("declares different inbounds", str(caught.exception))

    def test_a_computed_config_that_is_not_valid_json_is_refused(self):
        cluster = healthy_cluster()
        cluster["profiles"]["records"][0]["computed"] = {"status": 200, "parsed": False}
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("not valid JSON", str(caught.exception))

    def test_a_computed_config_that_failed_to_expand_is_refused(self):
        cluster = healthy_cluster()
        cluster["profiles"]["records"][1]["computed"] = {"status": 400, "parsed": False}
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("returned 400", str(caught.exception))

    def test_a_computed_config_with_the_wrong_inbound_count_is_refused(self):
        cluster = healthy_cluster()
        cluster["profiles"]["records"][0]["computed"]["inbound_count"] = 3
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("expands", str(caught.exception))

    def test_a_computed_config_without_outbounds_is_refused(self):
        cluster = healthy_cluster()
        cluster["profiles"]["records"][0]["computed"]["outbound_count"] = 0
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("no outbounds", str(caught.exception))

    def test_a_worker_host_dialling_the_master_domain_is_refused(self):
        cluster = healthy_cluster()
        worker_hosts = [
            record for record in cluster["hosts"]["records"]
            if record["nodes"] == [panel_surface.identifier(WORKER_NODE_UUID)]
        ]
        worker_hosts[1]["address"] = topology.PANEL_DOMAIN
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("instead of the Worker's own VPN address", str(caught.exception))

    def test_a_worker_without_a_published_host_is_refused(self):
        cluster = healthy_cluster()
        cluster["hosts"]["records"] = [
            record for record in cluster["hosts"]["records"]
            if record["nodes"] != [panel_surface.identifier(WORKER_NODE_UUID)]
        ]
        with self.assertRaises(AssertionError) as caught:
            self._run(multi_node.case_cluster_nodes, cluster)
        self.assertIn("no published host references the Worker", str(caught.exception))


class TestVisionCase(unittest.TestCase):
    """MN-VISION: the four combinations, and the defect each one rules out."""

    def _run(self, vision=False, worker_vision=False, cluster=None, node_facts=None):
        product = _VisionProduct(
            cluster if cluster is not None
            else healthy_cluster(vision=vision, worker_vision=worker_vision),
            cluster_node_facts(vision, worker_vision) if node_facts is None else node_facts,
            vision=vision, worker_vision=worker_vision,
        )
        return multi_node.case_vision_independence(product), product

    def test_each_combination_checks_both_nodes_against_their_own_names(self):
        for vision, worker_vision, combination in (
            (False, False, "neither"),
            (True, False, "master-only"),
            (False, True, "worker-only"),
            (True, True, "both"),
        ):
            with self.subTest(combination=combination):
                evidence, product = self._run(vision, worker_vision)
                self.assertEqual(evidence["combination"], combination)
                self.assertIs(evidence["master_vision_enabled"], vision)
                self.assertIs(evidence["worker_vision_enabled"], worker_vision)
                port = evidence["vision_internal_port"]
                self.assertEqual(product.vision_probes, [
                    ("master", topology.VISION_DOMAIN, port),
                    ("worker", topology.WORKER_VISION_DOMAIN, port),
                ])

    def test_a_node_without_vision_is_proven_to_have_no_endpoint_under_its_name(self):
        evidence, _product = self._run(False, False)
        self.assertIs(evidence["master_certificate"], False)
        self.assertIs(evidence["worker_certificate"], False)
        self.assertEqual(evidence["master_declared_vision_inbounds"], 0)
        self.assertEqual(evidence["worker_declared_vision_inbounds"], 0)
        self.assertEqual(evidence["master_applied_vision_inbounds"], 0)
        self.assertEqual(evidence["worker_applied_vision_inbounds"], 0)

    def test_the_inbound_is_matched_by_its_transport_not_by_its_tag(self):
        cluster = healthy_cluster(vision=True)
        vision_spec = cluster["nodes"]["records"][0]["inbound_specs"][-1]
        vision_spec["tag"] = "renamed-by-the-panel"
        evidence, _product = self._run(True, False, cluster=cluster)
        self.assertEqual(evidence["master_declared_vision_inbounds"], 1)

    def test_an_inbound_with_another_transport_port_is_not_taken_for_vision(self):
        cluster = healthy_cluster(vision=True)
        cluster["nodes"]["records"][0]["inbound_specs"][-1]["port"] = 9999
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, cluster=cluster)
        self.assertIn("declares 0 Vision inbounds", str(caught.exception))

    def test_a_vision_host_bound_to_another_node_is_refused(self):
        cluster = healthy_cluster(vision=True)
        master_vision_host = next(
            record for record in cluster["hosts"]["records"]
            if record["address"] == topology.VISION_DOMAIN
        )
        master_vision_host["nodes"] = [panel_surface.identifier(WORKER_NODE_UUID)]
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, cluster=cluster)
        self.assertIn("owns 0 Panel hosts", str(caught.exception))

    def test_a_certificate_that_does_not_cover_the_domain_is_refused(self):
        facts = cluster_node_facts(True, False)
        facts["master"]["certificate"]["host_ok"] = False
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, node_facts=facts)
        self.assertIn("does not cover the name", str(caught.exception))

    def test_a_route_pointing_at_another_port_is_refused(self):
        facts = cluster_node_facts(True, False)
        facts["master"]["nginx"]["stream_routes"] = [
            {"file": "gowave-stream.conf", "target": "127.0.0.1:9444;"},
        ]
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, node_facts=facts)
        self.assertIn("instead of exactly one 127.0.0.1:8444; route", str(caught.exception))

    def test_a_renewal_server_from_another_acme_directory_is_refused(self):
        facts = cluster_node_facts(True, False)
        facts["master"]["certificate"]["renewal_server"] = (
            "https://acme-v02.api.letsencrypt.org/directory"
        )
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, node_facts=facts)
        self.assertIn("renewal config asks", str(caught.exception))

    def test_an_applied_config_without_the_vision_inbound_is_refused(self):
        facts = cluster_node_facts(True, False)
        facts["master"]["applied"]["inbounds"] = applied_inbounds(False)
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, node_facts=facts)
        self.assertIn("carries 0 Vision inbounds", str(caught.exception))

    def test_an_applied_config_that_does_not_parse_is_refused(self):
        facts = cluster_node_facts(True, False)
        facts["worker"]["applied"] = {"parsed": False, "inbounds": []}
        with self.assertRaises(AssertionError) as caught:
            self._run(True, False, node_facts=facts)
        self.assertIn("no parseable applied config", str(caught.exception))

    def test_a_worker_carrying_a_certificate_without_vision_is_refused(self):
        facts = cluster_node_facts(False, False)
        facts["worker"]["certificate"].update({
            "present": True,
            "host_ok": True,
            "valid": True,
            "renewal_server": acme_fixture.ACME_DIRECTORY_URL,
        })
        with self.assertRaises(AssertionError) as caught:
            self._run(False, False, node_facts=facts)
        self.assertIn("holds a certificate", str(caught.exception))

    def test_a_node_that_still_routes_vision_without_it_is_refused(self):
        facts = cluster_node_facts(False, False)
        facts["worker"]["nginx"]["stream_routes"] = [
            {"file": "gowave-worker-stream.conf", "target": "127.0.0.1:8444;"},
        ]
        facts["worker"]["nginx"]["stream_vision_targets"] = ["gowave-worker-stream.conf"]
        with self.assertRaises(AssertionError) as caught:
            self._run(False, False, node_facts=facts)
        self.assertIn("routes Vision traffic", str(caught.exception))

    def test_a_worker_that_keeps_a_vision_vhost_without_it_is_refused(self):
        facts = cluster_node_facts(False, True)
        facts["master"]["nginx"]["vision_named_files"] = ["gowave-vision-fallback.conf"]
        with self.assertRaises(AssertionError) as caught:
            self._run(False, True, node_facts=facts)
        self.assertIn("keeps Vision vhosts", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
