#!/usr/bin/env python3
"""Suite nonroot: the Node API ingress matrix is judged from parsers, not a host.

FW-05, FW-06 and PO-FIREWALL assert four things about a disposable host. None of
them is a claim about a container this suite can build here, so what is held
below is the decision layer: given a rule set, a declaration and a second
reading, does the case name the failure it should and pass the shape it must?
The last group drives the case itself with fake readers, so the wiring — one
collection, one reload, both readings in the evidence — is proven without a
container. A closing group compares the operator section with the renderer, the
case registrations and the recovery module, so the page cannot describe a
policy the code does not apply. Container execution is reported separately by
the Podman run.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import ingress_matrix  # noqa: E402

MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
MASTER = "192.0.2.10"
OTHER = "198.51.100.9"


def load_managed():
    spec = importlib.util.spec_from_file_location("managed_renderer", str(MANAGED_PY))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def entries(sources):
    return [
        {"target": "ACCEPT", "source": source, "line": f"-A ufw-user-input -s {source} -j ACCEPT"}
        for source in sources
    ]


def blocks(sources=("",)):
    return [
        {"target": "DROP", "source": source, "line": "-A ufw-user-input -j DROP"}
        for source in sources
    ]


def family(**overrides):
    value = {
        "declared": "",
        "kernel_addresses": [],
        "kernel_disabled": True,
        "active": False,
        "allows": {},
        "blocks": {},
        "listens": {},
    }
    value.update(overrides)
    return value


def facts(
    allows=None,
    dropped=None,
    listeners=None,
    ipv6=None,
    active=True,
    chain_returncode=0,
    error="",
    default_incoming="deny",
):
    return {
        "active": active,
        "default_incoming": default_incoming,
        "allows": {int(port): entries(sources) for port, sources in (allows or {}).items()},
        "blocks": {int(port): blocks(sources) for port, sources in (dropped or {}).items()},
        "listeners": {int(port): list(addresses) for port, addresses in (listeners or {}).items()},
        "ipv6": ipv6 if ipv6 is not None else family(),
        "chain_returncode": chain_returncode,
        "error": error,
    }


SSH_OPEN = {22: [""]}
NODE_DENIED = {3002: [""]}


class TestNodeApiGaps(unittest.TestCase):
    def test_an_all_in_one_host_that_denies_the_port_to_every_source_passes(self):
        host = facts(allows=SSH_OPEN, dropped=NODE_DENIED, listeners={3002: ["0.0.0.0"]})
        self.assertEqual(ingress_matrix.node_api_gaps("aio", 3002, host, [22]), [])

    def test_a_public_allow_is_named(self):
        host = facts(allows={22: [""], 3002: [""]}, dropped=NODE_DENIED)
        gaps = ingress_matrix.node_api_gaps("aio", 3002, host, [22])
        self.assertTrue(any("allowed to every source" in gap for gap in gaps), gaps)

    def test_a_missing_deny_is_named(self):
        host = facts(allows=SSH_OPEN)
        gaps = ingress_matrix.node_api_gaps("aio", 3002, host, [22])
        self.assertTrue(any("no source-independent deny" in gap for gap in gaps), gaps)

    def test_an_all_in_one_grant_that_names_a_source_is_named(self):
        host = facts(allows={22: [""], 3002: [MASTER]}, dropped=NODE_DENIED)
        gaps = ingress_matrix.node_api_gaps("aio", 3002, host, [22])
        self.assertTrue(any(MASTER in gap for gap in gaps), gaps)

    def test_a_worker_naming_exactly_its_master_passes(self):
        host = facts(allows={22: [""], 3002: [MASTER]}, dropped=NODE_DENIED)
        self.assertEqual(ingress_matrix.node_api_gaps("worker", 3002, host, [22], [MASTER]), [])

    def test_a_worker_that_names_a_second_source_is_named(self):
        host = facts(allows={22: [""], 3002: [MASTER, OTHER]}, dropped=NODE_DENIED)
        gaps = ingress_matrix.node_api_gaps("worker", 3002, host, [22], [MASTER])
        self.assertTrue(any(OTHER in gap for gap in gaps), gaps)

    def test_a_worker_without_a_master_address_is_refused(self):
        host = facts(allows={22: [""], 3002: [MASTER]}, dropped=NODE_DENIED)
        gaps = ingress_matrix.node_api_gaps("worker", 3002, host, [22])
        self.assertTrue(any("no Master address" in gap for gap in gaps), gaps)

    def test_a_panel_only_host_with_no_rule_and_no_listener_passes(self):
        host = facts(allows=SSH_OPEN)
        self.assertEqual(ingress_matrix.node_api_gaps("panel-only", 3002, host, [22]), [])

    def test_a_panel_only_listener_is_named(self):
        host = facts(allows=SSH_OPEN, listeners={3002: ["0.0.0.0"]})
        gaps = ingress_matrix.node_api_gaps("panel-only", 3002, host, [22])
        self.assertTrue(any("listens on 3002" in gap for gap in gaps), gaps)

    def test_a_panel_only_allow_is_named(self):
        host = facts(allows={22: [""], 3002: [MASTER]})
        gaps = ingress_matrix.node_api_gaps("panel-only", 3002, host, [22])
        self.assertTrue(any("has no Node" in gap for gap in gaps), gaps)

    def test_an_inactive_firewall_is_named(self):
        host = facts(allows=SSH_OPEN, dropped=NODE_DENIED, active=False)
        gaps = ingress_matrix.node_api_gaps("aio", 3002, host, [22])
        self.assertTrue(any("not active" in gap for gap in gaps), gaps)

    def test_an_unreadable_rule_set_is_named(self):
        host = facts(allows=SSH_OPEN, dropped=NODE_DENIED, chain_returncode=4, error="denied")
        gaps = ingress_matrix.node_api_gaps("aio", 3002, host, [22])
        self.assertTrue(any("iptables -S" in gap for gap in gaps), gaps)
        self.assertTrue(any("could not be read" in gap for gap in gaps), gaps)

    def test_a_successful_probe_does_not_report_its_output_as_an_error(self):
        # `_HOST_FIREWALL` originally stored `(err or out)` as the error, so a
        # successful `iptables -L` handed its own rules back as a read failure
        # and FW-05 reported "the IPv4 rule set could not be read" on a healthy
        # host. A capture that falls back to stdout must be conditional on a
        # non-zero exit; `err or ""` (stderr only) is already empty on success.
        source = (REPO_ROOT / "tools" / "podman_e2e" / "denial.py").read_text(encoding="utf-8")
        offenders = [
            line for line in source.splitlines()
            if '_error"] =' in line and "(err or out)" in line and 'if code else ""' not in line
        ]
        self.assertEqual(offenders, [], "a probe error field keeps its success output as an error")

    def test_an_ssh_port_that_lost_its_public_allow_is_named(self):
        host = facts(allows={22: [MASTER], 3002: []}, dropped=NODE_DENIED)
        gaps = ingress_matrix.node_api_gaps("aio", 3002, host, [22])
        self.assertTrue(any("SSH port 22 is no longer reachable" in gap for gap in gaps), gaps)

    def test_an_unknown_role_is_refused(self):
        with self.assertRaises(ValueError):
            ingress_matrix.node_api_gaps("master", 3002, facts(allows=SSH_OPEN), [22])


class TestIpv6Mirror(unittest.TestCase):
    def test_a_kernel_without_ipv6_owes_no_v6_rule(self):
        host = facts(allows=SSH_OPEN, dropped=NODE_DENIED)
        self.assertEqual(ingress_matrix.ipv6_gaps("aio", 3002, host, [22]), [])

    def test_a_kernel_with_an_address_and_no_declaration_is_named(self):
        host = facts(
            allows=SSH_OPEN, dropped=NODE_DENIED,
            ipv6=family(kernel_addresses=["fe80::1"], kernel_disabled=False, declared="no"),
        )
        gaps = ingress_matrix.ipv6_gaps("aio", 3002, host, [22])
        self.assertTrue(any("IPV6=no" in gap for gap in gaps), gaps)

    def test_a_declared_but_unwritten_v6_chain_is_named(self):
        host = facts(
            allows=SSH_OPEN, dropped=NODE_DENIED,
            ipv6=family(kernel_addresses=["2001:db8::1"], kernel_disabled=False, declared="yes"),
        )
        gaps = ingress_matrix.ipv6_gaps("aio", 3002, host, [22])
        self.assertTrue(any("no ip6tables chain" in gap for gap in gaps), gaps)

    def test_a_v6_public_allow_is_named(self):
        host = facts(
            allows=SSH_OPEN, dropped=NODE_DENIED,
            ipv6=family(
                kernel_addresses=["2001:db8::1"], kernel_disabled=False, declared="yes",
                active=True, allows={22: entries([""]), 3002: entries([""])},
                blocks={3002: blocks()},
            ),
        )
        gaps = ingress_matrix.ipv6_gaps("aio", 3002, host, [22])
        self.assertTrue(any("over IPv6" in gap for gap in gaps), gaps)

    def test_the_worker_names_the_master_over_v6_too(self):
        mirrored = family(
            kernel_addresses=["2001:db8::1"], kernel_disabled=False, declared="yes", active=True,
            allows={22: entries([""]), 3002: entries([MASTER])}, blocks={3002: blocks()},
        )
        host = facts(allows={22: [""], 3002: [MASTER]}, dropped=NODE_DENIED, ipv6=mirrored)
        self.assertEqual(ingress_matrix.ipv6_gaps("worker", 3002, host, [22], [MASTER]), [])
        mirrored["allows"][3002] = entries([MASTER, OTHER])
        gaps = ingress_matrix.ipv6_gaps("worker", 3002, host, [22], [MASTER])
        self.assertTrue(any(OTHER in gap for gap in gaps), gaps)

    def test_a_panel_only_v6_listener_is_named(self):
        host = facts(
            allows=SSH_OPEN,
            ipv6=family(
                kernel_addresses=["2001:db8::1"], kernel_disabled=False, declared="yes",
                active=True, allows={22: entries([""])},
                listens={"*:3002": ["gowave-node"]},
            ),
        )
        gaps = ingress_matrix.ipv6_gaps("panel-only", 3002, host, [22])
        self.assertTrue(any("publishes 3002 over IPv6" in gap for gap in gaps), gaps)

    def test_ssh_must_stay_public_over_v6(self):
        host = facts(
            allows=SSH_OPEN, dropped=NODE_DENIED,
            ipv6=family(
                kernel_addresses=["2001:db8::1"], kernel_disabled=False, declared="yes",
                active=True, allows={22: entries([MASTER]), 3002: entries([])},
                blocks={3002: blocks()},
            ),
        )
        gaps = ingress_matrix.ipv6_gaps("aio", 3002, host, [22])
        self.assertTrue(any("over IPv6" in gap and "22" in gap for gap in gaps), gaps)


class TestDeclaredPolicy(unittest.TestCase):
    def setUp(self):
        self.managed = load_managed()

    def policies(self, role, ports, sources=()):
        return {
            port: self.managed.firewall_policy(role, [22], port, sources, False)
            for port in ports
        }

    def test_the_worker_declaration_is_the_same_for_any_port(self):
        policies = self.policies("worker", (3002, 3302), [MASTER])
        self.assertEqual(ingress_matrix.declared_policy_gaps("worker", policies, [MASTER]), [])

    def test_the_all_in_one_declaration_carries_no_source_grant(self):
        policies = self.policies("aio", (3002,))
        self.assertEqual(ingress_matrix.declared_policy_gaps("aio", policies), [])
        granted = self.policies("worker", (3002,), [MASTER])
        gaps = ingress_matrix.declared_policy_gaps("aio", granted)
        self.assertTrue(any("answers for role" in gap for gap in gaps), gaps)

    def test_a_panel_only_declaration_names_no_node_port(self):
        policies = self.policies("panel-only", (3002, 3302))
        self.assertEqual(ingress_matrix.declared_policy_gaps("panel-only", policies), [])

    def test_a_declaration_whose_deny_sits_before_the_allow_is_named(self):
        policies = self.policies("worker", (3002,), [MASTER])
        commands = policies[3002]["commands"]
        commands.remove(["deny", "3002/tcp"])
        commands.insert(2, ["deny", "3002/tcp"])
        gaps = ingress_matrix.declared_policy_gaps("worker", policies, [MASTER])
        self.assertTrue(any("the deny wins" in gap for gap in gaps), gaps)

    def test_a_declaration_that_lost_the_deny_is_named(self):
        policies = self.policies("worker", (3002,), [MASTER])
        policies[3002]["commands"].remove(["deny", "3002/tcp"])
        gaps = ingress_matrix.declared_policy_gaps("worker", policies, [MASTER])
        self.assertTrue(any("carries no deny" in gap for gap in gaps), gaps)

    def test_a_declaration_that_does_not_keep_ssh_is_named(self):
        policies = self.policies("aio", (3002,))
        policies[3002]["commands"].remove(["allow", "22/tcp"])
        gaps = ingress_matrix.declared_policy_gaps("aio", policies)
        self.assertTrue(any("SSH port 22" in gap for gap in gaps), gaps)

    def test_a_different_ssh_discovery_between_ports_is_named(self):
        policies = self.policies("worker", (3002, 3302), [MASTER])
        policies[3302]["ssh_ports"] = [22, 2222]
        gaps = ingress_matrix.declared_policy_gaps("worker", policies, [MASTER])
        self.assertTrue(any("discovers SSH ports" in gap for gap in gaps), gaps)

    def test_a_declaration_for_the_wrong_port_is_named(self):
        policies = self.policies("worker", (3002,), [MASTER])
        policies[3002]["node_port"] = 3302
        gaps = ingress_matrix.declared_policy_gaps("worker", policies, [MASTER])
        self.assertTrue(any("answers with node port" in gap for gap in gaps), gaps)

    def test_an_empty_read_is_named(self):
        self.assertEqual(
            ingress_matrix.declared_policy_gaps("aio", {}), ["no declared policy was read"],
        )


class TestReload(unittest.TestCase):
    def setUp(self):
        self.before = facts(allows={22: [""], 3002: [MASTER]}, dropped=NODE_DENIED)

    def after(self, unit=None, **overrides):
        value = facts(
            allows=overrides.pop("allows", {22: [""], 3002: [MASTER]}),
            dropped=overrides.pop("dropped", NODE_DENIED),
            **overrides,
        )
        value["unit"] = unit if unit is not None else {"enabled": "enabled", "active": "active"}
        return value

    def test_an_identical_second_reading_passes(self):
        self.assertEqual(
            ingress_matrix.reload_gaps(self.before, self.after(), [22, 3002]), [],
        )

    def test_a_lost_rule_is_named(self):
        lost = self.after(allows={22: [""]})
        gaps = ingress_matrix.reload_gaps(self.before, lost, [22, 3002])
        self.assertTrue(any("3002/tcp allows" in gap for gap in gaps), gaps)

    def test_a_unit_that_is_no_longer_enabled_is_named(self):
        gaps = ingress_matrix.reload_gaps(
            self.before, self.after({"enabled": "disabled", "active": "active"}), [22, 3002],
        )
        self.assertTrue(any("would not re-apply" in gap for gap in gaps), gaps)

    def test_a_failed_restart_is_named(self):
        gaps = ingress_matrix.reload_gaps(
            self.before,
            self.after({"enabled": "enabled", "active": "failed", "detail": "exit 1"}),
            [22, 3002],
        )
        self.assertTrue(any("'failed'" in gap for gap in gaps), gaps)

    def test_a_changed_default_policy_is_named(self):
        gaps = ingress_matrix.reload_gaps(
            self.before, self.after(default_incoming="allow"), [22, 3002],
        )
        self.assertTrue(any("default_incoming" in gap for gap in gaps), gaps)

    def test_a_second_reading_without_unit_state_is_named(self):
        gaps = ingress_matrix.reload_gaps(self.before, self.after({}), [22, 3002])
        self.assertTrue(any("persistence was not observed" in gap for gap in gaps), gaps)


class TestCaseDriver(unittest.TestCase):
    def run_case(self, role="worker", before=None, after=None, declared=None, sources=(MASTER,)):
        readings = []

        def collect(ports):
            readings.append(("collect", list(ports)))
            return before if before is not None else facts(
                allows={22: [""], 3002: [MASTER] if role == "worker" else ""},
                dropped=NODE_DENIED,
            )

        def reload(ports):
            readings.append(("reload", list(ports)))
            if after is not None:
                return after
            value = facts(
                allows={22: [""], 3002: [MASTER] if role == "worker" else ""},
                dropped=NODE_DENIED,
            )
            value["unit"] = {"enabled": "enabled", "active": "active"}
            return value

        evidence = ingress_matrix.case_ingress_matrix(
            ingress_matrix.CASE_IDS[role if role != "worker" else "multi-node"],
            role, 3002, collect, reload, [22], sources, declared,
        )
        return evidence, readings

    def test_a_green_host_records_both_readings(self):
        evidence, readings = self.run_case()
        self.assertEqual([name for name, _ in readings], ["collect", "reload"])
        self.assertEqual(evidence["verdict"], "allowed-only-from-the-master")
        self.assertEqual(evidence["ssh_ports"], [22])
        self.assertEqual(evidence["unit"], {"enabled": "enabled", "active": "active"})
        self.assertIn("3002", evidence["installed"]["ports"])

    def test_the_reload_is_taken_over_the_same_ports(self):
        _, readings = self.run_case()
        self.assertEqual(readings[0][1], readings[1][1])
        self.assertEqual(readings[0][1], [22, 3002])

    def test_a_gap_in_the_installed_rules_raises_with_its_port(self):
        broken = facts(allows={22: [""], 3002: [""]}, dropped=NODE_DENIED)
        with self.assertRaisesRegex(AssertionError, "FW-06: .*3002/tcp is allowed to every source"):
            self.run_case(before=broken)

    def test_a_gap_only_after_the_reload_raises(self):
        lost = facts(allows={22: [""]}, dropped=NODE_DENIED)
        lost["unit"] = {"enabled": "enabled", "active": "active"}
        with self.assertRaisesRegex(AssertionError, "after the reload 3002/tcp allows"):
            self.run_case(after=lost)

    def test_a_declared_gap_is_reported_with_the_installed_ones(self):
        renderer = load_managed()
        declared = {3002: renderer.firewall_policy("worker", [22], 3002, [MASTER], False)}
        declared[3002]["commands"].remove(["deny", "3002/tcp"])
        with self.assertRaisesRegex(AssertionError, "carries no deny"):
            self.run_case(declared=declared)

    def test_evidence_names_every_declared_port(self):
        renderer = load_managed()
        declared = {
            port: renderer.firewall_policy("panel-only", [22], port, [], False)
            for port in (ingress_matrix.DEFAULT_NODE_PORT, ingress_matrix.NON_DEFAULT_NODE_PORT)
        }
        evidence, _ = self.run_case(role="panel-only", declared=declared, sources=())
        self.assertEqual(
            evidence["declared_ports"],
            [ingress_matrix.DEFAULT_NODE_PORT, ingress_matrix.NON_DEFAULT_NODE_PORT],
        )


class TestCaseIdentity(unittest.TestCase):
    def test_every_role_has_one_case_id_and_its_own_verdict(self):
        self.assertEqual(
            ingress_matrix.CASE_IDS,
            {"aio": "FW-05", "multi-node": "FW-06", "panel-only": "PO-FIREWALL"},
        )
        self.assertEqual(sorted(ingress_matrix.VERDICTS), sorted(ingress_matrix.ROLES))

    def test_the_declared_port_the_install_never_uses_is_not_the_installed_one(self):
        self.assertNotEqual(
            ingress_matrix.NON_DEFAULT_NODE_PORT, ingress_matrix.DEFAULT_NODE_PORT,
        )


class TestIngressDocumentation(unittest.TestCase):
    """The page an operator reads has to agree with the code that decides.

    The section is the operator's only statement of which rule set a role
    receives, what the preflight refuses and how a failed change is undone. Each
    claim is compared with the module that owns it, so a renamed verdict, a
    dropped port or a moved recovery path fails here instead of reaching a host.
    """

    def setUp(self):
        self.document = (REPO_ROOT / "docs" / "SETUP_WIZARD.md").read_text(encoding="utf-8")

    def rows(self):
        rows = {}
        for line in self.document.splitlines():
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) == 4 and cells[0] in {f"`{role}`" for role in ingress_matrix.ROLES}:
                rows[cells[0].strip("`")] = cells
        return rows

    def test_the_table_states_each_role_with_the_verdict_the_case_asserts(self):
        rows = self.rows()
        self.assertEqual(sorted(rows), sorted(ingress_matrix.ROLES))
        for role, cells in rows.items():
            self.assertEqual(cells[3].strip("`"), ingress_matrix.VERDICTS[role], role)

    def test_the_panel_only_row_promises_no_node_port_and_the_rest_name_the_default(self):
        rows = self.rows()
        self.assertIn("none", rows["panel-only"][1].lower())
        for role in ("aio", "worker"):
            self.assertIn(str(ingress_matrix.DEFAULT_NODE_PORT), rows[role][1])
        self.assertIn(str(ingress_matrix.NON_DEFAULT_NODE_PORT), self.document)

    def test_every_port_the_renderer_protects_is_documented(self):
        policy = load_managed().firewall_policy(
            "aio", [22], ingress_matrix.DEFAULT_NODE_PORT, (), False,
        )
        for port in policy["internal_ports"]:
            self.assertIn(str(port), self.document, port)
        for port in policy["ssh_ports"] + [80, 443]:
            self.assertIn(f"`{port}`", self.document, port)

    def test_the_documented_worker_grant_is_the_rendered_one(self):
        renderer = load_managed()
        policy = renderer.firewall_policy(
            "worker", [22], ingress_matrix.DEFAULT_NODE_PORT, [MASTER], False,
        )
        self.assertIn(
            ["allow", "proto", "tcp", "from", MASTER, "to", "any", "port",
             str(ingress_matrix.DEFAULT_NODE_PORT)],
            policy["commands"],
        )
        self.assertIn("allow from the Master", self.document)
        panel = renderer.firewall_policy(
            "panel-only", [22], ingress_matrix.DEFAULT_NODE_PORT, (), False,
        )
        self.assertIsNone(panel["node_port"])
        node_rules = [command for command in panel["commands"]
                      if command[-1] == f"{ingress_matrix.DEFAULT_NODE_PORT}/tcp"]
        self.assertEqual(node_rules, [])

    def test_conflicts_preserved_exceptions_and_recovery_match_the_shipped_code(self):
        managed_source = MANAGED_PY.read_text(encoding="utf-8")
        self.assertIn("preserved_exceptions", managed_source)
        self.assertIn("`preserved_exceptions`", self.document)
        for path in ("'ufw'", "'user.rules'", "'user6.rules'"):
            self.assertIn(path, managed_source, path)
        for path in ("/etc/ufw/user.rules", "user6.rules"):
            self.assertIn(path, self.document, path)
        firewall = (REPO_ROOT / "modules" / "firewall.sh").read_text(encoding="utf-8")
        for claim in ("firewall-before-image", "/var/lib/gowave-auto-nginx/recovery",
                      "_FIREWALL_RESTORED", "already attempted"):
            self.assertIn(claim, firewall, claim)
        for claim in ("firewall-before-image", "/var/lib/gowave-auto-nginx/recovery",
                      "exactly one restore attempt"):
            self.assertIn(claim, self.document, claim)
        for claim in ("Маршрут восстановления", "ровно одна попытка восстановления",
                      "firewall-before-image"):
            self.assertIn(claim, self.document, claim)

    def test_the_cases_the_section_names_are_the_registered_ones(self):
        from tools.podman_e2e import catalog

        document = catalog.load_catalog()
        registered = {case["id"]: case.get("topology") or [] for case in document["cases"]}
        for topology, case_id in ingress_matrix.CASE_IDS.items():
            self.assertIn(case_id, registered, case_id)
            self.assertIn(topology, registered[case_id], case_id)
            self.assertIn(f"`{case_id}`", self.document, case_id)

    def test_both_operator_manuals_link_to_the_section_anchor(self):
        heading = next(line for line in self.document.splitlines()
                       if line.startswith("## Node API ingress and firewall recovery"))
        slug = re.sub(r"[^\w\s-]", "", heading.lstrip("# ").lower()).replace(" ", "-")
        link = f"docs/SETUP_WIZARD.md#{slug}"
        for name in ("README.md", "README.ru.md"):
            text = (REPO_ROOT / name).read_text(encoding="utf-8")
            self.assertIn(link, text, name)


if __name__ == "__main__":
    unittest.main()
