"""Suite nonroot: the required-input contract and the proxy refusal.

Both are pure-shell decisions that must run before the first host mutation, so
the tests drive the shipped functions rather than reading them: the contract is
sourced directly, and `resolve_node_inputs` is sliced out of `gowave-auto.sh`
and executed in a harness that already carries the contract.
"""
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT_SH = REPO_ROOT / "modules" / "preflight.sh"
WIZARD_SH = REPO_ROOT / "modules" / "wizard.sh"
GOWAVE_AUTO = REPO_ROOT / "gowave-auto.sh"
NODE_AUTO = REPO_ROOT / "gowave-node-auto.sh"

SOURCE_PREFLIGHT = f"source {shlex.quote(str(PREFLIGHT_SH))}\n"
SOURCE_WIZARD = f"source {shlex.quote(str(WIZARD_SH))}\n"


def bash(script, env=None):
    merged = dict(os.environ)
    for key in (
        "GOWAVE_PREFLIGHT_PROXY_CIDRS",
        "GOWAVE_PREFLIGHT_ALLOW_PROXIED",
        "GOWAVE_NODE_NAME",
        "GOWAVE_NODE_IP",
        "GOWAVE_WORKER_DOMAIN",
        "GOWAVE_REALITY_DOMAIN",
        "GOWAVE_SSH_USER",
        "GOWAVE_SSH_PORT",
        "GOWAVE_VISION_DOMAIN",
        "VISION_DOMAIN",
    ):
        merged.pop(key, None)
    merged.update(env or {})
    return subprocess.run(
        ["bash", "-c", script], text=True, capture_output=True, env=merged, timeout=120
    )


def function_text(name):
    text = GOWAVE_AUTO.read_text(encoding="utf-8")
    start = text.index(f"{name}() {{")
    return text[start:text.index("\n}\n", start) + 2]


class TestPreflightInputs(unittest.TestCase):
    def contract(self, component, *values):
        args = " ".join(shlex.quote(value) for value in values)
        return bash(f"{SOURCE_PREFLIGHT}preflight_require_inputs {component} {args}\n")

    def test_a_complete_install_invocation_passes(self):
        result = self.contract(
            "install", "panel.example.com", "cdn.example.com", "acme@example.com", ""
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_missing_panel_input_names_the_component_and_the_field(self):
        result = self.contract("install", "", "cdn.example.com", "acme@example.com", "")
        self.assertEqual(result.returncode, 2)
        self.assertIn("install requires the panel domain", result.stderr)
        self.assertIn("not provided", result.stderr)

    def test_a_malformed_email_names_the_field(self):
        result = self.contract("install", "panel.example.com", "cdn.example.com", "acme@example", "")
        self.assertEqual(result.returncode, 2)
        self.assertIn("install requires the ACME contact email", result.stderr)

    def test_panel_and_camouflage_must_differ(self):
        result = self.contract(
            "install", "SAME.example.com", "same.example.com", "acme@example.com", ""
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("differ", result.stderr)

    def test_vision_is_optional_but_validated(self):
        missing = self.contract(
            "install", "p.example.com", "c.example.com", "acme@example.com", ""
        )
        self.assertEqual(missing.returncode, 0, missing.stderr)
        malformed = self.contract(
            "install", "p.example.com", "c.example.com", "acme@example.com", "not_a_domain"
        )
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("the Vision domain", malformed.stderr)

    def test_a_complete_node_invocation_passes(self):
        result = self.contract(
            "node", "worker-1", "203.0.113.10", "worker-1.example.com", "cdn.example.com",
            "root", "22", "",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_missing_camouflage_domain_is_named(self):
        result = self.contract(
            "node", "worker-1", "203.0.113.10", "worker-1.example.com", "", "root", "22", ""
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("node requires the camouflage (REALITY) domain", result.stderr)

    def test_every_node_field_is_checked(self):
        good = ["worker-1", "203.0.113.10", "worker-1.example.com", "cdn.example.com",
                "root", "22", ""]
        cases = (
            (0, "bad name", "the Worker name"),
            (1, "not-an-ip", "the Worker address"),
            (1, "999.1.1.1", "the Worker address"),
            (2, "not_a_domain", "the Worker domain"),
            (3, "cdn", "the camouflage (REALITY) domain"),
            (4, "-bad", "the SSH user"),
            (5, "0", "the SSH port"),
            (5, "65536", "the SSH port"),
            (5, "22x", "the SSH port"),
            (6, "not_a_domain", "the Vision domain"),
        )
        for index, value, label in cases:
            with self.subTest(field=index, value=value):
                values = list(good)
                values[index] = value
                result = self.contract("node", *values)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(label, result.stderr)

    def test_a_valid_ipv6_address_is_accepted(self):
        result = self.contract(
            "node", "worker-1", "2001:db8::10", "worker-1.example.com", "cdn.example.com",
            "root", "22", "",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_unknown_component_is_refused(self):
        result = self.contract("nonsense")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown preflight component", result.stderr)

    def test_the_wizard_and_the_positional_path_refuse_the_same_value(self):
        candidates = (
            "example.com",
            "a.b",
            "panel-1.example.com",
            "EXAMPLE.COM",
            "bad_name.example.com",
            "bad..example.com",
            ".example.com",
            "example.com.",
            "localhost",
            "*.example.com",
            "exa mple.com",
            "a" * 64 + ".com",
        )
        script = SOURCE_WIZARD + "for candidate in \"$@\"; do\n"
        script += "  wizard=bad; preflight=bad\n"
        script += "  wizard_validate_hostname \"$candidate\" && wizard=ok\n"
        script += "  preflight_validate_hostname \"$candidate\" && preflight=ok\n"
        script += "  printf '%s\\t%s\\t%s\\n' \"$candidate\" \"$wizard\" \"$preflight\"\n"
        script += "done\n"
        result = subprocess.run(
            ["bash", "-c", script, "harness", *candidates],
            text=True, capture_output=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in result.stdout.splitlines() if "\t" in line]
        self.assertEqual(len(rows), len(candidates))
        for name, wizard, preflight in rows:
            self.assertEqual(wizard, preflight, f"the two paths disagree about {name!r}")


class TestNodeEnvironmentContract(unittest.TestCase):
    def run_resolver(self, env, *positionals):
        args = " ".join(shlex.quote(value) for value in positionals)
        script = (
            SOURCE_PREFLIGHT
            + function_text("resolve_node_inputs")
            + f"\nresolve_node_inputs {args}\n"
            + "printf 'name=%s\\naddress=%s\\nworker=%s\\nreality=%s\\nuser=%s\\nport=%s\\nvision=%s\\n' "
            + '"$NODE_INPUT_NAME" "$NODE_INPUT_ADDRESS" "$NODE_INPUT_WORKER_DOMAIN" '
            + '"$NODE_INPUT_REALITY_DOMAIN" "$NODE_INPUT_SSH_USER" "$NODE_INPUT_SSH_PORT" '
            + '"$NODE_INPUT_VISION_DOMAIN"\n'
        )
        return bash(script, env=env)

    def resolved(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    def environment(self, **overrides):
        values = {
            "GOWAVE_NODE_NAME": "worker-env",
            "GOWAVE_NODE_IP": "203.0.113.10",
            "GOWAVE_WORKER_DOMAIN": "worker-env.example.com",
            "GOWAVE_REALITY_DOMAIN": "cdn.example.com",
        }
        values.update(overrides)
        return values

    def test_an_environment_only_invocation_resolves_every_field(self):
        facts = self.resolved(self.run_resolver(self.environment()))
        self.assertEqual(facts["name"], "worker-env")
        self.assertEqual(facts["address"], "203.0.113.10")
        self.assertEqual(facts["worker"], "worker-env.example.com")
        self.assertEqual(facts["reality"], "cdn.example.com")
        self.assertEqual(facts["user"], "root")
        self.assertEqual(facts["port"], "22")
        self.assertEqual(facts["vision"], "")

    def test_an_empty_variable_counts_as_unset(self):
        result = self.run_resolver(self.environment(GOWAVE_SSH_USER="", GOWAVE_SSH_PORT=""))
        facts = self.resolved(result)
        self.assertEqual(facts["user"], "root")
        self.assertEqual(facts["port"], "22")

    def test_a_positional_overrides_its_variable(self):
        facts = self.resolved(
            self.run_resolver(
                self.environment(GOWAVE_NODE_NAME="worker-env", GOWAVE_SSH_PORT="2222"),
                "worker-pos", "", "", "", "", "2200",
            )
        )
        self.assertEqual(facts["name"], "worker-pos")
        self.assertEqual(facts["address"], "203.0.113.10", "an empty positional must not clear the variable")
        self.assertEqual(facts["port"], "2200")

    def test_the_flag_overrides_the_vision_variable(self):
        facts = self.resolved(
            self.run_resolver(
                self.environment(GOWAVE_VISION_DOMAIN="vision-env.example.com"),
                "", "", "", "", "", "", "vision-flag.example.com",
            )
        )
        self.assertEqual(facts["vision"], "vision-flag.example.com")

    def test_an_invalid_environment_value_is_refused_on_its_field(self):
        result = self.run_resolver(self.environment(GOWAVE_NODE_IP="not-an-ip"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("node requires the Worker address", result.stderr)

    def test_the_secret_is_not_an_input_of_this_contract(self):
        body = function_text("resolve_node_inputs")
        self.assertNotIn("SECRET", body)
        result = self.run_resolver(self.environment(GOWAVE_NODE_SECRET_KEY="sentinel-secret"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sentinel-secret", result.stdout + result.stderr)


class TestWorkerPayloadContract(unittest.TestCase):
    """The Worker side refuses the same fields, from the same module."""

    def contract(self, *values):
        args = " ".join(shlex.quote(value) for value in values)
        return bash(f"{SOURCE_PREFLIGHT}preflight_require_inputs worker {args}\n")

    def payload_main(self):
        text = NODE_AUTO.read_text(encoding="utf-8")
        # The payload entrypoint is the only line that starts with main(); the
        # derive_*_from_domain functions merely end in it.
        start = text.index("\nmain() {") + 1
        return text[start:text.index('\nmain "$@"', start)]

    def test_a_complete_worker_invocation_passes(self):
        result = self.contract("worker-1.example.com", "cdn.example.com", "", "3002")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_missing_worker_domain_is_named(self):
        result = self.contract("", "cdn.example.com", "", "3002")
        self.assertEqual(result.returncode, 2)
        self.assertIn("worker requires the Worker domain", result.stderr)

    def test_an_invalid_port_is_named(self):
        result = self.contract("worker-1.example.com", "cdn.example.com", "", "70000")
        self.assertEqual(result.returncode, 2)
        self.assertIn("worker requires the Worker port", result.stderr)

    def test_the_worker_and_camouflage_domains_must_differ(self):
        result = self.contract("same.example.com", "SAME.example.com", "", "3002")
        self.assertEqual(result.returncode, 2)
        self.assertIn("differ", result.stderr)

    def test_a_vision_name_is_validated_when_present(self):
        malformed = self.contract("worker-1.example.com", "cdn.example.com", "not_a_domain", "3002")
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("the Vision domain", malformed.stderr)
        duplicate = self.contract("worker-1.example.com", "cdn.example.com",
                                  "worker-1.example.com", "3002")
        self.assertEqual(duplicate.returncode, 2)
        self.assertIn("differ", duplicate.stderr)

    def test_the_payload_ships_the_module_instead_of_a_copy(self):
        text = NODE_AUTO.read_text(encoding="utf-8")
        self.assertEqual(text.count("preflight_require_inputs() {"), 0,
                         "the payload must not carry its own copy of the contract")
        self.assertEqual(text.count('cat "$preflight_module"'), 1)
        self.assertIn('preflight_module="$SCRIPT_DIR/modules/preflight.sh"', text)

    def test_the_contract_runs_before_the_first_mutation(self):
        body = self.payload_main()
        self.assertEqual(body.count("preflight_require_inputs worker"), 1,
                         "the Worker payload must call the contract exactly once")
        contract = body.index("preflight_require_inputs worker")
        self.assertLess(contract, body.index("bootstrap_early_tools"))
        self.assertLess(contract, body.index("acquire_mutation_lock"))
        self.assertLess(contract, body.index("verify_deploy_hook_preflight"))
        self.assertLess(contract, body.index("base64 -d > /run/gowave-acme-test-ca.pem"))
        # The traps that clean up after a refusal are installed before it.
        self.assertLess(body.index("trap 'handle_error"), contract)

    def test_there_is_exactly_one_payload_entrypoint_to_patch(self):
        # Task 3.2 counts the copies before the edit; this pins the count the
        # edit was made against, so a second entrypoint cannot appear silently.
        text = NODE_AUTO.read_text(encoding="utf-8")
        self.assertEqual(text.count("\nmain() {"), 1)


class TestPreflightProxyRefusal(unittest.TestCase):
    def resolver(self, directory, mapping):
        path = Path(directory) / "getent"
        marker = Path(directory) / "called"
        lines = ["#!/usr/bin/env bash", f'printf "%s\\n" "$2" >> {shlex.quote(str(marker))}']
        lines.append('case "$1" in')
        lines.append("  ahosts) ;;")
        lines.append("  *) exit 2 ;;")
        lines.append("esac")
        for name, address in mapping.items():
            lines.append(
                f'if [[ "$2" == {shlex.quote(name)} ]]; then '
                f"printf '%s STREAM %s\\n' {shlex.quote(address)} {shlex.quote(name)}; exit 0; fi"
            )
        lines.append("exit 2")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o755)
        # The directory, not the stub path: PATH is a list of directories, and a
        # file name there makes every lookup fall through to the real resolver.
        return str(Path(directory)), marker

    def direct_check(self, mapping, env=None, extra_args=()):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir, marker = self.resolver(directory, mapping)
            args = " ".join(shlex.quote(value) for value in ("panel.example.com",) + extra_args)
            merged = {"PATH": f"{bin_dir}:{os.environ['PATH']}"}
            merged.update(env or {})
            result = bash(
                f"{SOURCE_PREFLIGHT}preflight_require_direct_dns {args}\n", env=merged
            )
            called = marker.read_text(encoding="utf-8") if marker.exists() else ""
        return result, called

    def test_a_proxied_camouflage_name_stops_the_run(self):
        result, called = self.direct_check(
            {"panel.example.com": "203.0.113.10", "cdn.example.com": "104.16.1.2"},
            extra_args=("cdn.example.com",),
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("cdn.example.com resolves to 104.16.1.2", result.stderr)
        self.assertIn("DNS-only", result.stderr)
        self.assertIn("panel.example.com", called, "the check must ask the resolver, not assume")

    def test_a_proxied_panel_name_stops_the_run(self):
        result, _ = self.direct_check({"panel.example.com": "172.64.0.9"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("panel.example.com", result.stderr)

    def test_a_proxied_vision_name_stops_the_run(self):
        result, _ = self.direct_check(
            {
                "panel.example.com": "203.0.113.10",
                "cdn.example.com": "203.0.113.11",
                "vision.example.com": "2606:4700:3033::6815:1a2f",
            },
            extra_args=("cdn.example.com", "vision.example.com"),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("vision.example.com", result.stderr)

    def test_an_unproxied_deployment_proceeds(self):
        result, _ = self.direct_check(
            {"panel.example.com": "203.0.113.10", "cdn.example.com": "2001:db8::10"},
            extra_args=("cdn.example.com",),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_unresolvable_name_is_reported_not_guessed(self):
        result, _ = self.direct_check({"panel.example.com": "203.0.113.10"},
                                      extra_args=("missing.example.com",))
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not resolve missing.example.com", result.stderr)

    def test_an_explicit_override_is_honoured(self):
        result, _ = self.direct_check(
            {"panel.example.com": "104.16.1.2"},
            env={"GOWAVE_PREFLIGHT_ALLOW_PROXIED": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GOWAVE_PREFLIGHT_ALLOW_PROXIED=1", result.stderr)

    def test_an_operator_declared_range_replaces_the_snapshot(self):
        refused, _ = self.direct_check(
            {"panel.example.com": "203.0.113.10"},
            env={"GOWAVE_PREFLIGHT_PROXY_CIDRS": "203.0.113.0/24"},
        )
        self.assertEqual(refused.returncode, 1)
        self.assertIn("inside 203.0.113.0/24", refused.stderr)
        allowed, _ = self.direct_check(
            {"panel.example.com": "104.16.1.2"},
            env={"GOWAVE_PREFLIGHT_PROXY_CIDRS": "203.0.113.0/24"},
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def cidr(self, address, cidr):
        script = (
            SOURCE_PREFLIGHT
            + f"if preflight_cidr_match {shlex.quote(address)} {shlex.quote(cidr)}; "
            + "then echo inside; else echo outside; fi\n"
        )
        result = bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_ipv4_ranges_are_matched_by_prefix(self):
        self.assertEqual(self.cidr("104.16.5.5", "104.16.0.0/13"), "inside")
        self.assertEqual(self.cidr("104.23.255.255", "104.16.0.0/13"), "inside")
        self.assertEqual(self.cidr("104.32.0.1", "104.16.0.0/13"), "outside")
        self.assertEqual(self.cidr("203.0.113.10", "203.0.113.0/24"), "inside")

    def test_ipv6_ranges_are_matched_by_prefix(self):
        self.assertEqual(self.cidr("2606:4700:3033::6815:1a2f", "2606:4700::/32"), "inside")
        self.assertEqual(self.cidr("2606:4701::1", "2606:4700::/32"), "outside")
        # A /29 cuts inside the second group: 2a06:98c0..2a06:98c7.
        self.assertEqual(self.cidr("2a06:98c7::1", "2a06:98c0::/29"), "inside")
        self.assertEqual(self.cidr("2a06:98c8::1", "2a06:98c0::/29"), "outside")
        self.assertEqual(self.cidr("2001:db8::1", "2606:4700::/32"), "outside")

    def test_a_cross_family_range_never_matches(self):
        self.assertEqual(self.cidr("203.0.113.10", "2606:4700::/32"), "outside")
        self.assertEqual(self.cidr("2606:4700::1", "203.0.113.0/24"), "outside")


class TestPreflightDocumentation(unittest.TestCase):
    def test_every_documented_variable_is_read_by_the_contract(self):
        readmes = {
            name: (REPO_ROOT / name).read_text(encoding="utf-8")
            for name in ("README.md", "README.ru.md")
        }
        body = function_text("resolve_node_inputs")
        variables = (
            "GOWAVE_NODE_NAME",
            "GOWAVE_NODE_IP",
            "GOWAVE_WORKER_DOMAIN",
            "GOWAVE_REALITY_DOMAIN",
            "GOWAVE_SSH_USER",
            "GOWAVE_SSH_PORT",
            "GOWAVE_VISION_DOMAIN",
        )
        for variable in variables:
            for name, readme in readmes.items():
                with self.subTest(page=name, variable=variable):
                    self.assertIn(variable, readme, f"{name} does not document {variable}")
            self.assertIn(variable, body, f"resolve_node_inputs does not read {variable}")

    def test_the_usage_text_names_the_environment_contract(self):
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        usage = source[source.index('echo "Usage: gowave-auto.sh node add'):]
        usage = usage[: usage.index("\n", usage.index("\n") + 1)]
        for variable in ("GOWAVE_NODE_NAME", "GOWAVE_NODE_IP", "GOWAVE_WORKER_DOMAIN",
                         "GOWAVE_REALITY_DOMAIN", "GOWAVE_SSH_USER", "GOWAVE_SSH_PORT",
                         "GOWAVE_VISION_DOMAIN"):
            self.assertIn(variable, usage)


if __name__ == "__main__":
    unittest.main()
