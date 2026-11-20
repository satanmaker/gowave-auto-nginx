#!/usr/bin/env python3
"""Suite nonroot: the interactive setup wizard, its catalog and its budget.

Every test drives the sourced shell functions with scripted answers, so the
collected plan is observed rather than asserted from the source text. Two
exceptions read the source instead: the non-TTY entry runs the real CLI and
reads its refusal, and the guarded reachability of the catalog is asserted
against the shipped scripts, where a lookup could be added outside a function
a test can call.
"""
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOWAVE_AUTO = REPO_ROOT / "gowave-auto.sh"
INSTALL_ARGS_SH = REPO_ROOT / "modules" / "install_args.sh"
I18N_SH = REPO_ROOT / "modules" / "i18n.sh"
WIZARD_SH = REPO_ROOT / "modules" / "wizard.sh"

# Every script that ships to a host; the catalog belongs to the wizard alone.
SHIPPING_SCRIPTS = [
    REPO_ROOT / "gowave-auto.sh",
    REPO_ROOT / "gowave-node-auto.sh",
    *sorted((REPO_ROOT / "modules").glob("*.sh")),
    *sorted((REPO_ROOT / "assets").rglob("*.sh")),
]
# Every catalog key is namespaced `wizard.`, so a lookup is a `t` or `tf` call
# that names one, in a command substitution or not.
CATALOG_CALL = re.compile(r"\b(?:t|tf)\s+wizard\.")

SOURCE_WIZARD = f"source {shlex.quote(str(WIZARD_SH))}\n"


def bash(script, stdin="", env=None):
    merged = dict(os.environ)
    merged.pop("GOWAVE_WIZARD_LANG", None)
    merged.update(env or {})
    return subprocess.run(
        ["bash", "-c", script],
        input=stdin,
        text=True,
        capture_output=True,
        env=merged,
        timeout=120,
    )


def write_resolver(directory, failing=()):
    path = Path(directory) / "resolver"
    body = ["#!/bin/sh"]
    for name in failing:
        body.append(f'[ "$2" = {shlex.quote(name)} ] && exit 1')
    body.append("exit 0")
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


class TestWizardCatalog(unittest.TestCase):
    def test_both_catalogs_declare_the_same_keys(self):
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "printf 'EN\\n'\n"
            "printf '%s\\n' \"${!GOWAVE_I18N_EN[@]}\" | sort\n"
            "printf 'RU\\n'\n"
            "printf '%s\\n' \"${!GOWAVE_I18N_RU[@]}\" | sort\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        english, russian, current = [], [], None
        for line in result.stdout.splitlines():
            if line == "EN":
                current = english
                continue
            if line == "RU":
                current = russian
                continue
            if current is not None:
                current.append(line)
        self.assertTrue(english, "the English catalog is empty")
        self.assertEqual(english, russian, "the catalogs lost a key on one side")

    def test_a_missing_russian_entry_falls_back_to_english(self):
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=en\n"
            "english=$(t wizard.confirm)\n"
            "unset 'GOWAVE_I18N_RU[wizard.confirm]'\n"
            "GOWAVE_WIZARD_LANG=ru\n"
            "fallback=$(t wizard.confirm)\n"
            "printf '%s\\n%s\\n' \"$english\" \"$fallback\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        english, fallback = result.stdout.splitlines()
        self.assertNotEqual(english, "wizard.confirm")
        self.assertEqual(fallback, english)

    def test_an_unknown_key_returns_its_own_name(self):
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=ru\n"
            "t wizard.no.such.key\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "wizard.no.such.key")

    def test_the_selector_defaults_to_english_and_rejects_an_unknown_value(self):
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "unset GOWAVE_WIZARD_LANG\n"
            "printf 'default=%s\\n' \"$(wizard_language)\"\n"
            "set_wizard_language ru && printf 'ru=%s\\n' \"$(wizard_language)\"\n"
            "set_wizard_language fr || printf 'rejected\\n'\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("default=en", lines)
        self.assertIn("ru=ru", lines)
        self.assertIn("rejected", lines)

    def test_russian_selection_translates_a_prompt(self):
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=ru\n"
            "t wizard.confirm\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, "[А-Яа-я]")


class TestHostnameValidation(unittest.TestCase):
    def _verdicts(self, candidates):
        result = bash(
            SOURCE_WIZARD
            + "while IFS= read -r candidate; do\n"
            "  if wizard_validate_hostname \"$candidate\"; then printf '%s\\tok\\n' \"$candidate\";"
            " else printf '%s\\tbad\\n' \"$candidate\"; fi\n"
            "done\n",
            stdin="\n".join(candidates) + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("\t") for line in result.stdout.splitlines() if "\t" in line)

    def test_valid_names_are_accepted(self):
        names = ["example.com", "a.b", "panel-1.example.com", "EXAMPLE.COM", "x.y.z.example.org"]
        verdicts = self._verdicts(names)
        for name in names:
            self.assertEqual(verdicts[name], "ok", name)

    def test_invalid_names_are_rejected(self):
        names = [
            "-bad.example.com",
            "bad-.example.com",
            "bad_name.example.com",
            "bad..example.com",
            ".example.com",
            "example.com.",
            "localhost",
            "*.example.com",
            "exa mple.com",
            "a" * 64 + ".com",
        ]
        verdicts = self._verdicts(names)
        for name in names:
            self.assertEqual(verdicts[name], "bad", name)

    def test_a_name_longer_than_the_dns_limit_is_rejected(self):
        verdicts = self._verdicts(["a." * 127 + "com"])
        self.assertEqual(list(verdicts.values()), ["bad"])

    def test_an_email_needs_a_domain_and_a_tld(self):
        result = bash(
            SOURCE_WIZARD
            + "for candidate in admin@example.com admin@example bad@admin@example.com; do\n"
            "  if wizard_validate_email \"$candidate\"; then echo \"$candidate ok\";"
            " else echo \"$candidate bad\"; fi\n"
            "done\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("admin@example.com ok", result.stdout)
        self.assertIn("admin@example bad", result.stdout)
        self.assertIn("bad@admin@example.com bad", result.stdout)


class TestPlanRegistration(unittest.TestCase):
    def test_a_duplicate_camouflage_name_is_refused_without_mutating_the_plan(self):
        result = bash(
            SOURCE_WIZARD
            + "wizard_register_host panel p.example.com c.example.com || exit 9\n"
            "if wizard_register_host worker w.example.com c.example.com; then echo SECOND_OK;"
            " else echo SECOND_REFUSED; fi\n"
            "printf 'nodes=%s\\n' \"${#GOWAVE_PLAN_NODE_NAMES[@]}\"\n"
            "printf 'panel=%s\\n' \"$GOWAVE_PLAN_PANEL_NAME\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SECOND_REFUSED", result.stdout)
        self.assertIn("nodes=0", result.stdout)
        self.assertIn("panel=p.example.com", result.stdout)
        self.assertIn("c.example.com", result.stderr)

    def test_the_same_name_twice_for_one_host_is_refused(self):
        result = bash(
            SOURCE_WIZARD
            + "if wizard_register_host panel same.example.com same.example.com; then echo ACCEPTED;"
            " else echo REFUSED; fi\n"
            "printf 'panel=%s\\n' \"$GOWAVE_PLAN_PANEL_NAME\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("panel=", result.stdout)
        self.assertNotIn("panel=same.example.com", result.stdout)

    def test_an_invalid_name_is_refused_without_mutating_the_plan(self):
        result = bash(
            SOURCE_WIZARD
            + "if wizard_register_host panel bad_name.example.com c.example.com; then echo ACCEPTED;"
            " else echo REFUSED; fi\n"
            "printf 'panel=%s\\n' \"$GOWAVE_PLAN_PANEL_NAME\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertNotIn("panel=bad_name.example.com", result.stdout)

    def test_an_over_long_label_is_refused_before_any_mutation(self):
        label = "a" * 64 + ".example.com"
        result = bash(
            SOURCE_WIZARD
            + f"if wizard_register_host worker {shlex.quote(label)} c.example.com; then echo ACCEPTED;"
            " else echo REFUSED; fi\n"
            "printf 'nodes=%s\\n' \"${#GOWAVE_PLAN_NODE_NAMES[@]}\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("nodes=0", result.stdout)


DUMP_PLAN = (
    "printf 'variant=%s\\n' \"$GOWAVE_PLAN_VARIANT\"\n"
    "printf 'panel=%s\\n' \"$GOWAVE_PLAN_PANEL_NAME\"\n"
    "printf 'camouflage=%s\\n' \"$GOWAVE_PLAN_CAMOUFLAGE_NAME\"\n"
    "printf 'vision=%s\\n' \"$GOWAVE_PLAN_VISION_NAME\"\n"
    "printf 'email=%s\\n' \"$GOWAVE_PLAN_EMAIL\"\n"
    "printf 'shared=%s\\n' \"$GOWAVE_PLAN_SHARED_DOMAIN\"\n"
    "printf 'cert_count=%s\\n' \"$(wizard_plan_certificate_count)\"\n"
    "for i in \"${!GOWAVE_PLAN_NODE_NAMES[@]}\"; do\n"
    "  printf 'node=%s|%s|%s\\n' \"${GOWAVE_PLAN_NODE_NAMES[$i]}\""
    " \"${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}\" \"${GOWAVE_PLAN_NODE_VISION[$i]:-}\"\n"
    "done\n"
)


class TestCollectPlan(unittest.TestCase):
    def _collect(self, answers, failing=()):
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory, failing)
            result = bash(
                SOURCE_WIZARD
                + "if wizard_collect_plan >/dev/null; then echo CONFIRMED; else echo REFUSED; fi\n"
                + DUMP_PLAN,
                stdin=answers,
                env={"GOWAVE_WIZARD_RESOLVER": resolver},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        verdict = lines[0] if lines else ""
        values = dict(line.split("=", 1) for line in lines[1:] if "=" in line and "|" not in line)
        nodes = [line.split("=", 1)[1] for line in lines[1:] if line.startswith("node=")]
        return verdict, values, nodes, result.stderr

    def test_all_in_one_collects_a_panel_host_with_vision(self):
        verdict, values, nodes, _ = self._collect(
            "en\n1\npanel.example.com\ncdn.example.com\ny\nvision.example.com\n"
            "admin@example.com\nn\ny\n"
        )
        self.assertEqual(verdict, "CONFIRMED")
        self.assertEqual(values["variant"], "all-in-one")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["vision"], "vision.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertEqual(values["shared"], "no")
        self.assertEqual(values["cert_count"], "3")
        self.assertEqual(nodes, [])

    def test_panel_only_collects_its_workers_and_no_panel_vision(self):
        # A panel-only host runs no local node, so the workers are the whole
        # traffic plane and the plan has to ask for them.
        verdict, values, nodes, _ = self._collect(
            "en\n2\npanel.example.com\ncdn.example.com\nadmin@example.com\n2\n"
            "node1.example.com\ncdn1.example.com\nn\n"
            "node2.example.com\ncdn2.example.com\ny\nvision2.example.com\nn\ny\n"
        )
        self.assertEqual(verdict, "CONFIRMED")
        self.assertEqual(values["variant"], "panel-only")
        self.assertEqual(values["vision"], "")
        self.assertEqual(values["cert_count"], "7")
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|vision2.example.com"],
        )

    def test_multi_node_collects_every_worker_and_its_optional_vision(self):
        verdict, values, nodes, _ = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\ny\nvision.example.com\n"
            "admin@example.com\n2\n"
            "node1.example.com\ncdn1.example.com\nn\n"
            "node2.example.com\ncdn2.example.com\ny\nvision2.example.com\n"
            "n\ny\n"
        )
        self.assertEqual(verdict, "CONFIRMED")
        self.assertEqual(values["variant"], "multi-node")
        self.assertEqual(values["cert_count"], "8")
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|vision2.example.com"],
        )

    def test_a_plan_with_an_unresolvable_name_is_refused_before_confirmation(self):
        verdict, values, nodes, stderr = self._collect(
            "en\n1\npanel.example.com\nmissing.example.com\nn\nadmin@example.com\nn\ny\n",
            failing=("missing.example.com",),
        )
        self.assertEqual(verdict, "REFUSED")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(nodes, [])
        self.assertIn("missing.example.com", stderr)
        self.assertNotIn("These names do not resolve: panel.example.com", stderr)

    def test_a_rejected_variant_answer_and_a_bad_node_count_repeat_the_question(self):
        verdict, values, _, _ = self._collect(
            "en\n9\n1\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\nn\ny\n"
        )
        self.assertEqual(verdict, "CONFIRMED")
        self.assertEqual(values["variant"], "all-in-one")

        verdict, values, _, _ = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\n0\n1\n"
            "node1.example.com\ncdn1.example.com\nn\nn\ny\n"
        )
        self.assertEqual(verdict, "CONFIRMED")
        self.assertEqual(values["cert_count"], "4")


class TestCertificateBudget(unittest.TestCase):
    def test_the_four_ceilings_match_the_published_table(self):
        result = bash(
            SOURCE_WIZARD
            + "printf 'none-no=%s\\n' \"$(wizard_certificate_ceiling no none)\"\n"
            "printf 'none-yes=%s\\n' \"$(wizard_certificate_ceiling yes none)\"\n"
            "printf 'all-no=%s\\n' \"$(wizard_certificate_ceiling no all)\"\n"
            "printf 'all-yes=%s\\n' \"$(wizard_certificate_ceiling yes all)\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["none-no=24", "none-yes=23", "all-no=16", "all-yes=15"],
        )

    def test_the_count_formula_sits_on_each_boundary(self):
        result = bash(
            SOURCE_WIZARD
            + "printf 'base=%s\\n' \"$(wizard_certificate_count no 0 0)\"\n"
            "printf 'at24=%s\\n' \"$(wizard_certificate_count no 24 0)\"\n"
            "printf 'above24=%s\\n' \"$(wizard_certificate_count no 25 0)\"\n"
            "printf 'at23v=%s\\n' \"$(wizard_certificate_count yes 23 0)\"\n"
            "printf 'above23v=%s\\n' \"$(wizard_certificate_count yes 24 0)\"\n"
            "printf 'at16all=%s\\n' \"$(wizard_certificate_count no 16 16)\"\n"
            "printf 'above16all=%s\\n' \"$(wizard_certificate_count no 17 17)\"\n"
            "printf 'at15all=%s\\n' \"$(wizard_certificate_count yes 15 15)\"\n"
            "printf 'above15all=%s\\n' \"$(wizard_certificate_count yes 16 16)\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "base=2",
                "at24=50",
                "above24=52",
                "at23v=49",
                "above23v=51",
                "at16all=50",
                "above16all=53",
                "at15all=48",
                "above15all=51",
            ],
        )


class TestCertificatePreflight(unittest.TestCase):
    def _preflight(self, script, stdin=""):
        return bash(SOURCE_WIZARD + script, stdin=stdin)

    def test_separate_registered_domains_proceed_silently(self):
        result = self._preflight(
            "GOWAVE_PLAN_SHARED_DOMAIN=no\n"
            "GOWAVE_PLAN_PANEL_VISION=no\n"
            "wizard_certificate_preflight && echo PROCEED\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PROCEED", result.stdout)
        self.assertIn("own Let's Encrypt budget", result.stdout)

    def test_a_shared_domain_above_the_ceiling_is_refused_with_count_and_ceiling(self):
        result = self._preflight(
            "GOWAVE_PLAN_SHARED_DOMAIN=yes\n"
            "GOWAVE_PLAN_PANEL_VISION=yes\n"
            "GOWAVE_PLAN_NODE_COUNT=24\n"
            "if wizard_certificate_preflight; then echo PROCEED; else echo REFUSED; fi\n"
        )
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("51", result.stderr)
        self.assertIn("23", result.stderr)

    def test_a_shared_domain_within_the_ceiling_needs_an_explicit_yes(self):
        base = (
            "GOWAVE_PLAN_SHARED_DOMAIN=yes\n"
            "GOWAVE_PLAN_PANEL_VISION=no\n"
            "GOWAVE_PLAN_NODE_COUNT=4\n"
        )
        refused = self._preflight(
            base + "if wizard_certificate_preflight; then echo PROCEED; else echo REFUSED; fi\n",
            stdin="n\n",
        )
        self.assertIn("REFUSED", refused.stdout)
        self.assertIn("10", refused.stderr)

        accepted = self._preflight(
            base + "if wizard_certificate_preflight; then echo PROCEED; else echo REFUSED; fi\n",
            stdin="y\n",
        )
        self.assertIn("PROCEED", accepted.stdout)


class TestWizardEntry(unittest.TestCase):
    def test_an_argument_less_install_without_a_terminal_names_the_arguments(self):
        result = subprocess.run(
            ["bash", str(GOWAVE_AUTO), "install"],
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=120,
            env={k: v for k, v in os.environ.items() if k != "GOWAVE_WIZARD_LANG"},
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Usage: gowave-auto.sh install", result.stderr)
        self.assertIn("terminal", result.stderr)

    def test_a_partial_install_without_a_terminal_names_the_missing_arguments(self):
        # A flag-only invocation used to fall through to the prompts, and `read`
        # under `set -e` exited 1 with nothing on either stream.
        result = subprocess.run(
            ["bash", str(GOWAVE_AUTO), "install", "--panel-only"],
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=120,
            env={k: v for k, v in os.environ.items() if k != "GOWAVE_WIZARD_LANG"},
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Usage: gowave-auto.sh install", result.stderr)
        for argument in ("the panel or worker name", "the camouflage name", "the acme email"):
            with self.subTest(argument=argument):
                self.assertIn(argument, result.stderr)
        self.assertNotIn("needs a terminal to run the setup wizard", result.stderr)

    def test_the_wizard_is_unreachable_when_any_argument_is_present(self):
        result = bash(
            f"source {shlex.quote(str(INSTALL_ARGS_SH))}\n"
            f"{SOURCE_WIZARD}"
            "if wizard_should_run panel.example.com cdn.example.com admin@example.com;"
            " then echo WIZARD; else echo POSITIONAL; fi\n"
            "if wizard_should_run; then echo WIZARD; else echo POSITIONAL; fi\n",
            stdin="",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["POSITIONAL", "POSITIONAL"])

    def test_apply_plan_renders_the_documented_argument_shape(self):
        result = bash(
            f"source {shlex.quote(str(INSTALL_ARGS_SH))}\n"
            f"{SOURCE_WIZARD}"
            "GOWAVE_PLAN_VARIANT=all-in-one\n"
            "GOWAVE_PLAN_PANEL_NAME=p.example.com\n"
            "GOWAVE_PLAN_CAMOUFLAGE_NAME=c.example.com\n"
            "GOWAVE_PLAN_EMAIL=admin@example.com\n"
            "GOWAVE_PLAN_VISION_NAME=v.example.com\n"
            "wizard_apply_plan\n"
            "printf 'mode=%s args=%s\\n' \"$GOWAVE_INSTALL_MODE\" \"${GOWAVE_INSTALL_POSITIONAL[*]}\"\n"
            "GOWAVE_PLAN_VARIANT=panel-only\n"
            "GOWAVE_PLAN_VISION_NAME=v.example.com\n"
            "wizard_apply_plan\n"
            "printf 'mode=%s args=%s count=%s\\n' \"$GOWAVE_INSTALL_MODE\""
            " \"${GOWAVE_INSTALL_POSITIONAL[*]}\" \"${#GOWAVE_INSTALL_POSITIONAL[@]}\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("mode=all-in-one args=p.example.com c.example.com admin@example.com v.example.com", lines)
        self.assertIn("mode=panel-only args=p.example.com c.example.com admin@example.com count=3", lines)

    def test_the_positional_path_reaches_no_catalog_lookup(self):
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        install_body = source[source.index("cmd_install() {"):]
        install_body = install_body[: install_body.index("\ncmd_node() {")]
        self.assertIn('if wizard_should_run "$@"', install_body)
        self.assertLess(
            install_body.index('if wizard_should_run "$@"'),
            install_body.index("wizard_collect_plan"),
        )
        self.assertLess(
            install_body.index("wizard_collect_plan"),
            install_body.index("parse_install_arguments"),
        )
        self.assertNotRegex(
            install_body,
            CATALOG_CALL,
            "cmd_install renders a catalog entry of its own; only the wizard may",
        )
        self.assertIn('wizard_onboard_nodes || return 1', install_body)
        self.assertLess(
            install_body.index('case "${GOWAVE_PLAN_VARIANT:-}" in'),
            install_body.index("wizard_onboard_nodes"),
            "a positional install must not reach the translated onboarding",
        )
        prompts = re.findall(r'read -r -p "([^"]*)"', install_body)
        self.assertTrue(prompts, "cmd_install lost its positional prompts")
        for prompt in prompts:
            self.assertTrue(prompt.isascii(), f"a positional prompt is translated: {prompt}")

    def test_the_catalog_is_reachable_only_from_the_wizard_and_its_ssh_helper(self):
        callers = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in SHIPPING_SCRIPTS
            if CATALOG_CALL.search(path.read_text(encoding="utf-8"))
        )
        self.assertEqual(
            callers,
            ["modules/ssh_bootstrap.sh", "modules/wizard.sh"],
            "a shipped script outside the wizard renders a translated string",
        )

    def test_the_ssh_helper_is_reached_only_through_a_collected_plan(self):
        # The definition lives in that module; every other mention is a caller.
        callers = [
            path.relative_to(REPO_ROOT).as_posix()
            for path in SHIPPING_SCRIPTS
            if path.name not in ("wizard.sh", "ssh_bootstrap.sh")
            and "ssh_bootstrap_onboard_one" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(callers, [], "a shipped script outside the wizard onboards a node")

    def test_a_complete_argument_list_collects_a_plan_without_the_catalog(self):
        result = bash(
            f"source {shlex.quote(str(INSTALL_ARGS_SH))}\n"
            + SOURCE_WIZARD
            + "t() { printf 'CATALOG:%s\\n' \"$1\" >&2; return 1; }\n"
            "tf() { printf 'CATALOG:%s\\n' \"$1\" >&2; return 1; }\n"
            "wizard_collect_plan() { printf 'WIZARD\\n' >&2; return 1; }\n"
            "wizard_apply_plan() { printf 'WIZARD\\n' >&2; return 1; }\n"
            "if wizard_should_run panel.example.com cdn.example.com admin@example.com;"
            " then echo ENTERED; else echo SKIPPED; fi\n"
            "parse_install_arguments panel.example.com cdn.example.com admin@example.com\n"
            "printf 'mode=%s count=%s args=%s\\n' \"$GOWAVE_INSTALL_MODE\""
            " \"${#GOWAVE_INSTALL_POSITIONAL[@]}\" \"${GOWAVE_INSTALL_POSITIONAL[*]}\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", "the positional path asked a question or read the catalog")
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "SKIPPED",
                "mode=all-in-one count=3 args=panel.example.com cdn.example.com admin@example.com",
            ],
        )


class TestWizardDocumentation(unittest.TestCase):
    """The three domain limits and the two SSH variables are policy, not prose."""

    def test_the_readme_names_the_three_limits_and_both_variables(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("remaining budget cannot be queried", readme)
        self.assertIn("belongs to a single host", readme)
        self.assertIn("wildcard is not a remedy", readme)
        self.assertIn("gowave_ssh_fingerprint", readme)
        self.assertIn("gowave_ssh_password_file", readme)

    def test_the_design_names_the_three_limits(self):
        design = (REPO_ROOT / "openspec/changes/interactive-setup-wizard/design.md").read_text(
            encoding="utf-8"
        ).lower()
        self.assertIn("remaining budget cannot be queried", design)
        self.assertIn("can only belong to one host", design)
        self.assertIn("wildcard certificates are not the escape hatch", design)

    def test_the_operator_document_names_the_three_limits_and_both_variables(self):
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8").lower()
        self.assertIn("remaining budget cannot be queried", document)
        self.assertIn("belongs to a single host", document)
        self.assertIn("wildcard is not a remedy", document)
        self.assertIn("gowave_ssh_fingerprint", document)
        self.assertIn("gowave_ssh_password_file", document)


if __name__ == "__main__":
    unittest.main()
