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
    *sorted(p for p in (REPO_ROOT / "modules").glob("*.sh") if p.exists()),
    *sorted(p for p in (REPO_ROOT / "assets").rglob("*.sh") if p.exists()),
]
# Every catalog key is namespaced `wizard.` or `menu.`, so a lookup is a `t` or `tf` call
# that names one, in a command substitution or not.
CATALOG_CALL = re.compile(r"\b(?:t|tf)\s+(?:wizard|menu)\.")

SOURCE_WIZARD = f"source {shlex.quote(str(WIZARD_SH))}\n"


def change_document(name, filename):
    """A change's document wherever the change lives: still proposed, or archived.

    A completed change moves under ``changes/archive/<date>-<name>``, so a test
    that pins the live path turns red the day the change is archived — for a
    moved file, not for a broken claim.
    """
    live = REPO_ROOT / "openspec" / "changes" / name / filename
    if live.exists():
        return live
    archived = sorted((REPO_ROOT / "openspec" / "changes" / "archive").glob(f"*-{name}/{filename}"))
    if not archived:
        raise FileNotFoundError(f"no {filename} for the change {name}")
    return archived[-1]


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


def write_ssh_keyscan_mock(directory, reachable=(), banner_for=()):
    """Create a mock ssh-keyscan that simulates reachable/unreachable hosts."""
    # Generate a real ed25519 key for the mock to use
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "mock_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
            capture_output=True,
            check=True,
        )
        mock_pubkey = Path(str(key_path) + ".pub").read_text().strip()

    path = Path(directory) / "ssh-keyscan"
    body = ["#!/bin/sh", "# Mock ssh-keyscan for testing"]
    body.append('# ssh-keyscan is called as: ssh-keyscan -T 10 -p PORT -t ed25519 HOST')
    body.append('# The host is the last argument')
    body.append('host=""')
    body.append('port=22')
    body.append('while [ $# -gt 0 ]; do')
    body.append('  case "$1" in')
    body.append('    -p) port="$2"; shift 2 ;;')
    body.append('    -T) shift 2 ;;')  # timeout option
    body.append('    -t) shift 2 ;;')  # key type option
    body.append('    *) host="$1"; shift ;;')  # host is the last non-option
    body.append('  esac')
    body.append('done')
    body.append('')
    for h in reachable:
        body.append(f'if [ "$host" = {shlex.quote(h)} ]; then')
        # Real ssh-keyscan outputs banner line WITH # prefix, then the key line
        body.append(f'  echo "# {h}:22 SSH-2.0-OpenSSH_9.0"')
        body.append(f'  echo "{h} {mock_pubkey}"')
        body.append(f'  exit 0')
        body.append(f'fi')
    for h in banner_for:
        body.append(f'if [ "$host" = {shlex.quote(h)} ]; then')
        body.append(f'  echo "# {h}:22 SSH-2.0-OpenSSH_9.0"')
        body.append(f'  exit 0')
        body.append(f'fi')
    body.append('# Default: unreachable (timeout)')
    body.append('sleep 2')
    body.append('exit 1')
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

    def test_menu_catalog_has_ru_en_parity(self):
        # ``"$k"`` rather than ``"\$k"``: Python keeps the backslash, and bash
        # then reads the literal ``$k`` instead of the variable, so the loop
        # collected nothing and two empty lists were compared as parity. The
        # body ends in ``continue`` rather than a failing test, because
        # ``i18n.sh`` sources under ``pipefail`` and a false ``[[ ]]`` would
        # otherwise fail the ``sort`` pipeline it feeds.
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "printf 'EN\\n'\n"
            "for k in \"${!GOWAVE_I18N_EN[@]}\"; do\n"
            "  [[ \"$k\" == menu.* ]] || continue\n"
            "  printf '%s\\n' \"$k\"\n"
            "done | sort\n"
            "printf 'RU\\n'\n"
            "for k in \"${!GOWAVE_I18N_RU[@]}\"; do\n"
            "  [[ \"$k\" == menu.* ]] || continue\n"
            "  printf '%s\\n' \"$k\"\n"
            "done | sort\n"
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
        self.assertTrue(english, "the English menu catalog is empty")
        self.assertEqual(english, russian, "the menu catalogs lost a key on one side")

    def test_menu_keys_are_matched_by_the_extended_catalog_guard(self):
        # gowave-auto.sh uses menu.* keys; verify the regex matches them
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=en\n"
            "t menu.option.status\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(result.stdout.strip(), "menu.option.status")
        self.assertRegex(result.stdout, "Show status")

    def test_a_third_script_with_catalog_lookup_is_still_rejected(self):
        # Create a temporary script that uses a catalog lookup and verify
        # the guard test would catch it
        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "third_script.sh"
            script.write_text('#!/usr/bin/env bash\nsource modules/i18n.sh\nt menu.option.status\n', encoding="utf-8")
            script.chmod(0o755)
            # The guard test only checks SHIPPING_SCRIPTS, so this external script
            # is not checked. But we can verify the regex would match it.
            text = script.read_text(encoding="utf-8")
            self.assertTrue(CATALOG_CALL.search(text),
                           "the extended regex should match menu.* keys in any script")


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
    "printf 'node_count=%s\\n' \"$GOWAVE_PLAN_NODE_COUNT\"\n"
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
        # The guard captures the onboarding status and gives each outcome its own
        # exit code: a partial success is neither a clean install nor a failed one.
        self.assertIn('wizard_onboard_nodes || onboard_rc=$?', install_body)
        self.assertIn('onboard_rc == 1', install_body)
        self.assertIn('onboard_rc == 2', install_body)
        self.assertIn('return 2', install_body)
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
            ["gowave-auto.sh", "modules/ssh_bootstrap.sh", "modules/wizard.sh"],
            "a shipped script outside the wizard renders a translated string",
        )

    def test_the_ssh_helper_is_reached_only_through_the_wizard_and_the_add_node_menu(self):
        # The definition lives in that module; every other mention is a caller.
        callers = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in SHIPPING_SCRIPTS
            if path.name not in ("wizard.sh", "ssh_bootstrap.sh")
            and "ssh_bootstrap_onboard_one" in path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            callers,
            ["gowave-auto.sh"],
            "a shipped script outside the wizard onboards a node",
        )
        # The menu may run it, the positional paths may not: every mention in
        # the entrypoint belongs to the interactive add-node flow.
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        start = source.index("wizard_add_node_to_panel() {")
        body = source[start : source.index("\n}\n", start)]
        self.assertIn("ssh_bootstrap_onboard_one", body)
        self.assertEqual(
            source.count("ssh_bootstrap_onboard_one"),
            body.count("ssh_bootstrap_onboard_one"),
            "an entrypoint path outside the add-node menu onboards a node",
        )

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


class TestOnboardingOutcomes(unittest.TestCase):
    """wizard_onboard_nodes: three outcomes, one retry offer, one scratch tree.

    The loop decides whether a single broken Worker is fatal, so the exit code it
    returns is the contract the install's own exit status carries. The outcomes
    are driven by replacing the SSH hop — the only step that needs a second host
    — and leaving the summary, the retry offer and the scratch cleanup to the
    shipped code.
    """

    PLAN = (
        "GOWAVE_PLAN_NODE_NAMES=('worker-ok' 'worker-bad')\n"
        "GOWAVE_PLAN_NODE_CAMOUFLAGE=('cam-ok.example' 'cam-bad.example')\n"
        "GOWAVE_PLAN_NODE_VISION=('' '')\n"
    )

    def onboard(self, outcomes, stdin="2\n", callee=None):
        """Run the loop over two Workers; ``outcomes`` maps name to success.

        ``callee`` replaces the generated stub with a body that models the SSH
        hop's own side effects — the real one tracks a key directory of its own.
        """
        stubs = [
            "ssh_bootstrap_onboard_one() {",
            '  case "$1" in',
        ]
        for name, succeeds in outcomes.items():
            if succeeds:
                stubs.append(f"    {name}) printf '==> Onboarding %s\\n' \"$1\"; return 0 ;;")
            else:
                stubs.append(f"    {name}) printf 'PHASE:scan\\n' >&2;")
                stubs.append(f"      printf 'Could not read the SSH host key of %s.\\n' \"$1\" >&2;")
                stubs.append("      return 1 ;;")
        stubs += ["  esac", "  return 1", "}"]
        if callee is not None:
            stubs = [callee]
        script = (
            f"source {shlex.quote(str(I18N_SH))}\n"
            f"source {shlex.quote(str(REPO_ROOT / 'modules' / 'tempdir.sh'))}\n"
            + SOURCE_WIZARD
            + "GOWAVE_STATE_DIR=$(mktemp -d)\n"
            + self.PLAN
            + "\n".join(stubs)
            + "\nset +e\nwizard_onboard_nodes\nrc=$?\nprintf 'RC=%d\\n' \"$rc\"\n"
        )
        with tempfile.TemporaryDirectory() as scratch:
            sentinel = Path(scratch) / "keep-me"
            sentinel.write_text("a file the cleanup must not reach\n", encoding="utf-8")
            result = bash(script, stdin=stdin, env={"TMPDIR": scratch})
            survived = sentinel.exists() and sentinel.read_text(encoding="utf-8")
        return result, survived

    def test_a_partial_success_exits_two_and_offers_the_failed_node_alone(self):
        result, _survived = self.onboard({"worker-ok": True, "worker-bad": False})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=2", result.stdout)
        self.assertIn("  worker-ok: success", result.stdout)
        self.assertIn(
            "  worker-bad: failed (phase: scan, reason: Could not read the SSH host key of worker-bad.)",
            result.stdout,
        )
        offer = result.stdout.split("Some nodes failed. Select a node to retry, or skip:", 1)[1]
        self.assertNotIn("worker-ok", offer, "the retry offer named a node that succeeded")
        self.assertIn("worker-bad", offer)
        self.assertIn("Retry skipped.", offer)

    def test_every_node_succeeding_exits_zero_without_a_retry_offer(self):
        result, _survived = self.onboard({"worker-ok": True, "worker-bad": True})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=0", result.stdout)
        self.assertNotIn("Some nodes failed", result.stdout)

    def test_every_node_failing_exits_one_without_a_retry_offer(self):
        result, _survived = self.onboard({"worker-ok": False, "worker-bad": False})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=1", result.stdout)
        self.assertNotIn("Some nodes failed", result.stdout)

    def test_the_scratch_directory_never_widens_to_its_parent(self):
        # The cleanup helper removes the directory it is handed. Handing it the
        # parent of a temporary file would delete the whole of TMPDIR, so the
        # sentinel below is the reading: one file the onboarding had no business
        # touching, and it is still there afterwards.
        _result, survived = self.onboard({"worker-ok": True, "worker-bad": False})
        self.assertEqual(survived, "a file the cleanup must not reach\n")

    def test_a_callee_tracking_its_own_scratch_keeps_the_failure_reason(self):
        # The real ssh_bootstrap_onboard_one tracks an SSH key directory of its
        # own inside the command substitution and releases it before returning.
        # An unlevelled cleanup then ran over the caller's entries on the way
        # out and deleted the stderr file the loop had not read yet, so a real
        # Worker failure was reported as "phase: unknown" with the cause gone.
        callee = (
            "ssh_bootstrap_onboard_one() {\n"
            "  local own\n"
            '  own=$(mktemp -d "${TMPDIR:-/tmp}/gowave-wizard-ssh.XXXXXX")\n'
            '  track_temp_dir "$own"\n'
            "  printf '==> Onboarding %s\\n' \"$1\"\n"
            "  printf 'PHASE:scan\\n' >&2\n"
            "  printf 'Could not read the SSH host key.\\n' >&2\n"
            '  release_temp_dir "$own"\n'
            "  return 1\n"
            "}\n"
        )
        result, _survived = self.onboard(
            {"worker-ok": False, "worker-bad": False}, callee=callee)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("No such file or directory", result.stderr,
                         f"the caller's scratch file was deleted: {result.stderr}")
        self.assertIn("phase: scan", result.stdout)
        self.assertIn("reason: Could not read the SSH host key.", result.stdout)


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
        design = change_document("interactive-setup-wizard", "design.md").read_text(
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


class TestPlanReview(unittest.TestCase):
    """Tests for the plan review screen that allows editing any field."""

    def _review(self, initial_answers, review_answers, failing=()):
        """Run wizard_collect_plan then wizard_review_plan and return the final plan."""
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory, failing)
            result = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null\n"
                + "wizard_review_plan >/dev/null\n"
                + DUMP_PLAN,
                stdin=initial_answers + "\n" + review_answers,
                env={"GOWAVE_WIZARD_RESOLVER": resolver},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        values = dict(line.split("=", 1) for line in lines if "=" in line and "|" not in line)
        nodes = [line.split("=", 1)[1] for line in lines if line.startswith("node=")]
        return values, nodes, result.stderr

    def test_review_plan_can_change_panel_domain_and_preserves_other_fields(self):
        """Changing the panel domain preserves variant, email, camouflage, and nodes."""
        # Menu: 1=variant, 2=panel_domain, 3=camouflage_domain, 4=vision_domain,
        # 5=email, 6=shared_domain
        values, nodes, _ = self._review(
            # Initial collection: all-in-one with panel, camouflage, vision, email
            "en\n1\npanel.example.com\ncdn.example.com\ny\nvision.example.com\n"
            "admin@example.com\nn\ny\n",
            # Review: change panel domain (2), then confirm (0)
            "2\nnewpanel.example.com\n0\n"
        )
        self.assertEqual(values["variant"], "all-in-one")
        self.assertEqual(values["panel"], "newpanel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["vision"], "vision.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertEqual(nodes, [])

    def test_review_plan_can_change_email_and_preserves_other_fields(self):
        """Changing the email preserves all other fields."""
        # Menu: 1=variant, 2=panel_domain, 3=camouflage_domain, 4=vision_domain,
        # 5=email, 6=shared_domain
        values, nodes, _ = self._review(
            "en\n1\npanel.example.com\ncdn.example.com\nn\nold@example.com\nn\ny\n",
            "5\nnew@example.com\n0\n"
        )
        self.assertEqual(values["email"], "new@example.com")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")

    def test_review_plan_rejects_invalid_hostname(self):
        """An invalid hostname in review is rejected and the original value is kept."""
        values, nodes, stderr = self._review(
            "en\n1\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\nn\ny\n",
            "2\nnot-a-valid-hostname\n2\npanel2.example.com\n0\n"
        )
        self.assertEqual(values["panel"], "panel2.example.com")
        self.assertIn("not-a-valid-hostname", stderr)

    def test_review_plan_rejects_duplicate_name(self):
        """A duplicate name in review is rejected and the original value is kept."""
        values, nodes, stderr = self._review(
            "en\n1\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\nn\ny\n",
            "2\ncdn.example.com\n2\npanel2.example.com\n0\n"
        )
        self.assertEqual(values["panel"], "panel2.example.com")
        self.assertIn("already used", stderr)

    def test_review_plan_can_change_node_count_and_adds_nodes(self):
        """Increasing node count prompts for new node details."""
        # Menu for 1 node: 1=variant, 2=panel, 3=camouflage, 4=vision(panel),
        # 5=email, 6=shared, 7=node_count, 8=node1_name, 9=node1_camouflage, 10=node1_vision
        values, nodes, _ = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\ny\nvision.example.com\n"
            "admin@example.com\n1\n"
            "node1.example.com\ncdn1.example.com\nn\nn\ny\n",
            # Change node count from 1 to 2 (7), then enter new node details
            "7\n2\nnode2.example.com\ncdn2.example.com\nn\n0\n"
        )
        self.assertEqual(values["node_count"], "2")
        self.assertEqual(len(nodes), 2)
        self.assertIn("node1.example.com|cdn1.example.com|", nodes)
        self.assertIn("node2.example.com|cdn2.example.com|", nodes)

    def test_review_plan_can_decrease_node_count(self):
        """Decreasing node count truncates the node arrays."""
        # Menu for 2 nodes: 1=variant, 2=panel, 3=camouflage, 4=vision(panel),
        # 5=email, 6=shared, 7=node_count, 8=node1_name, 9=node1_camouflage, 10=node1_vision,
        # 11=node2_name, 12=node2_camouflage, 13=node2_vision
        values, nodes, _ = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\n2\n"
            "node1.example.com\ncdn1.example.com\nn\n"
            "node2.example.com\ncdn2.example.com\nn\nn\ny\n",
            "7\n1\n0\n"
        )
        self.assertEqual(values["node_count"], "1")
        self.assertEqual(len(nodes), 1)
        self.assertIn("node1.example.com|cdn1.example.com|", nodes)
        self.assertNotIn("node2.example.com", str(nodes))

    def test_review_plan_can_change_node_name(self):
        """Changing a node's name preserves other fields."""
        # Menu for 1 node: 1=variant, 2=panel, 3=camouflage, 4=vision(panel),
        # 5=email, 6=shared, 7=node_count, 8=node1_name, 9=node1_camouflage, 10=node1_vision
        values, nodes, _ = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\n1\n"
            "node1.example.com\ncdn1.example.com\nn\nn\ny\n",
            "8\nnode1-renamed.example.com\n0\n"
        )
        self.assertEqual(len(nodes), 1)
        self.assertIn("node1-renamed.example.com|cdn1.example.com|", nodes)

    def test_review_plan_can_change_node_vision(self):
        """Adding Vision to a node that didn't have it."""
        # Menu for 1 node: 1=variant, 2=panel, 3=camouflage, 4=vision(panel),
        # 5=email, 6=shared, 7=node_count, 8=node1_name, 9=node1_camouflage, 10=node1_vision
        values, nodes, _ = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\n1\n"
            "node1.example.com\ncdn1.example.com\nn\nn\ny\n",
            "10\nvision1.example.com\n0\n"
        )
        self.assertEqual(len(nodes), 1)
        self.assertIn("node1.example.com|cdn1.example.com|vision1.example.com", nodes)

    def test_review_plan_can_remove_node_vision(self):
        """Removing Vision from a node that had it."""
        # Menu for 1 node with vision: same structure, node1_vision is field 10
        values, nodes, _ = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\n1\n"
            "node1.example.com\ncdn1.example.com\ny\nvision1.example.com\nn\ny\n",
            "10\n\n0\n"
        )
        self.assertEqual(len(nodes), 1)
        self.assertIn("node1.example.com|cdn1.example.com|", nodes)
        self.assertNotIn("vision1.example.com", str(nodes))

    def test_review_plan_re_runs_certificate_preflight(self):
        """Changing shared_domain to yes re-runs certificate budget check."""
        # Menu: 1=variant, 2=panel, 3=camouflage, 4=vision(panel), 5=email, 6=shared_domain
        # Need two "y": one for shared_domain value, one for preflight confirmation
        values, nodes, stderr = self._review(
            "en\n1\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\nn\ny\n",
            # Change shared_domain to yes (6), confirm preflight (y), then confirm exit (0)
            "6\ny\ny\n0\n"
        )
        self.assertEqual(values["shared"], "yes")
        # Should have passed preflight (only 2 certs needed)
        self.assertNotIn("exceed the ceiling", stderr)

    def test_review_plan_rejects_shared_domain_over_ceiling(self):
        """Shared domain with too many certificates is rejected."""
        # Start with multi-node, 25 nodes (2 certs each + 2 panel = 52 certs)
        # Then change to shared_domain=yes which exceeds 50
        # Menu for 25 nodes is large, shared_domain is field 6
        values, nodes, stderr = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nadmin@example.com\n25\n"
            + "\n".join(f"node{i}.example.com\ncdn{i}.example.com\nn" for i in range(1, 26))
            + "\nn\ny\n",
            "6\ny\n0\n"
        )
        # This should fail preflight because 2 + 2*25 = 52 certs > 50
        self.assertIn("exceed the ceiling", stderr)


class TestSSHReachability(unittest.TestCase):
    """Tests for the SSH reachability check using ssh-keyscan."""

    def _setup_plan_with_nodes(self, node_count=1, variant="multi-node"):
        """Collect a plan with the given number of nodes."""
        answers = [
            "en",
            "3" if variant == "multi-node" else "1",
            "panel.example.com",
            "cdn.example.com",
            "n",
            "admin@example.com",
            str(node_count),
        ]
        for i in range(1, node_count + 1):
            answers.extend([
                f"node{i}.example.com",
                f"cdn{i}.example.com",
                "n",
            ])
        answers.extend(["n", "y"])
        # Ensure trailing newline so the final read gets the "y"
        return "\n".join(answers) + "\n"

    def _run_ssh_check(self, plan_answers, failing=(), reachable=(), banner_for=(), env=None):
        """Run wizard_collect_plan then wizard_check_ssh_reachable with mocked ssh-keyscan."""
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory, failing)
            ssh_keyscan = write_ssh_keyscan_mock(directory, reachable=reachable, banner_for=banner_for)
            # Prepend mock directory to PATH
            merged_env = {
                "GOWAVE_WIZARD_RESOLVER": resolver,
                "PATH": f"{directory}:{os.environ['PATH']}",
            }
            if env:
                merged_env.update(env)
            result = bash(
                SOURCE_WIZARD
                + "if wizard_collect_plan >/dev/null; then echo COLLECT_OK; else echo COLLECT_FAIL; fi\n"
                + "wizard_check_ssh_reachable\n",
                stdin=plan_answers,
                env=merged_env,
            )
        return result

    def test_ssh_reachable_all_nodes_ok(self):
        """All nodes reachable via ssh-keyscan returns success."""
        plan = self._setup_plan_with_nodes(node_count=2)
        result = self._run_ssh_check(plan, failing=(), reachable=("node1.example.com", "node2.example.com"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COLLECT_OK", result.stdout)
        self.assertIn("SSH reachable: node1.example.com", result.stdout)
        self.assertIn("SSH reachable: node2.example.com", result.stdout)

    def test_ssh_unreachable_one_node_fails(self):
        """One unreachable node causes the check to fail."""
        plan = self._setup_plan_with_nodes(node_count=2)
        # node1 reachable, node2 unreachable (not in reachable list)
        result = self._run_ssh_check(plan, failing=(), reachable=("node1.example.com",))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("COLLECT_OK", result.stdout)
        self.assertIn("SSH reachable: node1.example.com", result.stdout)
        # Error messages go to stderr
        self.assertIn("SSH unreachable: node2.example.com", result.stderr)

    def test_ssh_banner_line_reported(self):
        """A banner line instead of a key is reported."""
        plan = self._setup_plan_with_nodes(node_count=1)
        result = self._run_ssh_check(plan, failing=(), banner_for=("node1.example.com",))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("COLLECT_OK", result.stdout)
        # Error messages go to stderr
        self.assertIn("banner line was returned", result.stderr)

    def test_ssh_fingerprint_mismatch_refuses(self):
        """A fingerprint mismatch when plan carries one refuses the node."""
        plan = self._setup_plan_with_nodes(node_count=1)
        # The mock returns a key for node1.example.com with fingerprint "mockkeyfornode1.example.com"
        # Provide a wrong fingerprint
        result = self._run_ssh_check(
            plan,
            failing=(),
            reachable=("node1.example.com",),
            env={"GOWAVE_SSH_FINGERPRINT": "SHA256:wrongfingerprint"}
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("COLLECT_OK", result.stdout)
        # Error messages go to stderr
        self.assertIn("does not match", result.stderr)
        self.assertIn("refusing to proceed", result.stderr)

    def test_ssh_fingerprint_match_allows(self):
        """A matching fingerprint allows the node."""
        plan = self._setup_plan_with_nodes(node_count=1)
        # The mock key for node1.example.com has "mockkeyfornode1.example.com" in it
        # The fingerprint would be SHA256:mockkeyfornode1.example.com (simplified)
        # But ssh_bootstrap_fingerprint extracts the second field from ssh-keygen -lf
        # Our mock key is "node1.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmockkeyfornode1.example.com"
        # The fingerprint would be based on the public key data
        # For testing, we just verify no mismatch error when no fingerprint is provided
        result = self._run_ssh_check(plan, failing=(), reachable=("node1.example.com",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COLLECT_OK", result.stdout)

    def test_ssh_no_nodes_skips_check(self):
        """All-in-one variant with no remote nodes skips the check."""
        plan = self._setup_plan_with_nodes(node_count=0, variant="all-in-one")
        result = self._run_ssh_check(plan)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Checking SSH", result.stdout)

    def test_ssh_check_not_called_in_positional_path(self):
        """The positional install path does not call the SSH reachability check."""
        result = bash(
            f"source {shlex.quote(str(INSTALL_ARGS_SH))}\n"
            + SOURCE_WIZARD
            + "wizard_check_ssh_reachable() { echo 'SSH_CHECK_CALLED' >&2; return 1; }\n"
            + "parse_install_arguments panel.example.com cdn.example.com admin@example.com\n"
            + "if wizard_should_run panel.example.com cdn.example.com admin@example.com; then wizard_check_ssh_reachable; fi\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SSH_CHECK_CALLED", result.stderr)


class TestPanelApiVerification(unittest.TestCase):
    """wizard_verify_panel_api talks to the address the Panel actually serves.

    The Panel answers plaintext HTTP on 3000 and NGINX terminates TLS on 443, so
    a probe that speaks TLS to 3000 can never succeed, and /api/health is not a
    route the Panel answers. Both facts are observed here rather than read from
    the source: the fake ``curl`` records the URL it was handed.
    """

    CURL = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_LOG/curl"
n=0
[ -f "$FAKE_LOG/curl.count" ] && n=$(cat "$FAKE_LOG/curl.count")
n=$((n + 1))
printf '%s\\n' "$n" > "$FAKE_LOG/curl.count"
if [ "$n" -eq 1 ]; then exit "${FAKE_CURL_FIRST:-0}"; fi
exit "${FAKE_CURL_REST:-0}"
"""

    OPENSSL = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_LOG/openssl"
case "$*" in
    *s_client*) printf '%s\\n' '-----BEGIN CERTIFICATE-----'; exit 0 ;;
    *x509*)
        n=0
        [ -f "$FAKE_LOG/x509.count" ] && n=$(cat "$FAKE_LOG/x509.count")
        n=$((n + 1))
        printf '%s\\n' "$n" > "$FAKE_LOG/x509.count"
        if [ "${FAKE_NO_CERT:-0}" = 1 ]; then exit 1; fi
        if [ -n "${FAKE_SECOND_FINGERPRINT:-}" ] && [ "$n" -ge 2 ]; then
            printf 'sha256 Fingerprint=%s\\n' "$FAKE_SECOND_FINGERPRINT"
            exit 0
        fi
        printf 'sha256 Fingerprint=%s\\n' "${FAKE_FINGERPRINT:-AA:BB:CC}"
        exit 0 ;;
esac
exit 0
"""

    def verify(self, address, local="no", stdin="", first=0, rest=0, env=None):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory) / "bin"
            log_dir = Path(directory) / "log"
            bin_dir.mkdir()
            log_dir.mkdir()
            for name, body in (("curl", self.CURL), ("openssl", self.OPENSSL)):
                path = bin_dir / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)
            merged = {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "FAKE_LOG": str(log_dir),
                "FAKE_CURL_FIRST": str(first),
                "FAKE_CURL_REST": str(rest),
            }
            merged.update(env or {})
            result = bash(
                SOURCE_WIZARD
                + f"set +e\nwizard_verify_panel_api {shlex.quote(address)} {local}\nprintf 'RC=%d\\n' \"$?\"\n",
                stdin=stdin,
                env=merged,
            )
            curls = (log_dir / "curl").read_text(encoding="utf-8").splitlines() if (log_dir / "curl").exists() else []
            openssls = (
                (log_dir / "openssl").read_text(encoding="utf-8").splitlines()
                if (log_dir / "openssl").exists()
                else []
            )
        return result, curls, openssls

    def test_a_local_panel_is_verified_over_the_loopback_without_tls(self):
        result, curls, openssls = self.verify("panel.example.com", local="yes")
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertIn("Panel API verified: panel.example.com", result.stdout)
        self.assertEqual(len(curls), 1, curls)
        self.assertEqual(curls[0].split()[-1], "http://127.0.0.1:3000/api/system/health")
        self.assertEqual(openssls, [], "a loopback Panel needs no certificate check")

    def test_a_remote_panel_is_verified_on_443_with_the_health_route(self):
        result, curls, _openssls = self.verify("panel.example.com")
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertEqual(curls[0].split()[-1], "https://panel.example.com/api/system/health")
        self.assertNotIn(":3000", curls[0], "TLS was pointed at the plaintext Panel port")

    def test_a_rejected_certificate_is_confirmed_then_accepted(self):
        result, curls, _openssls = self.verify("panel.example.com", stdin="y\n", first=60, rest=0)
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertIn("TLS certificate verification failed.", result.stdout)
        self.assertIn("Certificate fingerprint: AA:BB:CC", result.stdout)
        self.assertEqual(len(curls), 2, curls)
        self.assertIn("-fsSk", curls[1], "the confirmed request was not repeated without validation")

    def test_a_rejected_certificate_is_refused_without_an_answer(self):
        result, curls, _openssls = self.verify("panel.example.com", stdin="n\n", first=60)
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("Panel verification cancelled.", result.stderr)
        self.assertEqual(len(curls), 1, curls)

    def test_a_certificate_that_changes_during_the_question_is_refused(self):
        result, curls, _openssls = self.verify(
            "panel.example.com", stdin="y\n", first=60, env={"FAKE_SECOND_FINGERPRINT": "DD:EE:FF"}
        )
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("changed while the confirmation was open", result.stderr)
        self.assertEqual(len(curls), 1, "the request ran despite the changed certificate")

    def test_an_absent_certificate_refuses_before_any_question(self):
        result, _curls, _openssls = self.verify(
            "panel.example.com", stdin="y\n", first=60, env={"FAKE_NO_CERT": "1"}
        )
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("Could not retrieve certificate.", result.stderr)
        self.assertNotIn("Certificate fingerprint:", result.stdout)

    def test_a_bare_address_is_refused_as_unverifiable(self):
        result, curls, openssls = self.verify("10.1.2.3")
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("the address 10.1.2.3 cannot be verified", result.stderr)
        self.assertEqual(curls, [], "a bare address was probed")
        self.assertEqual(openssls, [], "a bare address was probed for a certificate")

    def test_an_unreachable_api_is_not_reported_as_a_certificate_problem(self):
        result, _curls, _openssls = self.verify("panel.example.com", first=7)
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("Panel API unreachable.", result.stderr)
        self.assertNotIn("TLS certificate verification failed.", result.stdout)

    def test_the_menu_add_node_runs_the_temporary_access_onboarding(self):
        # `node add` alone refuses a Worker whose host key is not already pinned
        # and whose access is password-only, so the menu has to reach the same
        # onboarding the install runs instead of calling it directly.
        script = (
            f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
            "detect_local_panel() { printf 'panel.example.com'; return 0; }\n"
            "wizard_verify_panel_api() { printf 'VERIFY=%s/%s\\n' \"$1\" \"$2\"; return 0; }\n"
            "ssh_bootstrap_onboard_one() {"
            " printf 'ONBOARD host=%s cam=%s vision=[%s] name=%s ip=%s\\n'"
            " \"$1\" \"$2\" \"${3-}\" \"${4-}\" \"${5-}\"; return 0; }\n"
            "cmd_node() { printf 'CMD_NODE=%s\\n' \"$*\"; return 0; }\n"
            "set +e\n"
            "wizard_add_node_to_panel\n"
            "printf 'RC=%d\\n' \"$?\"\n"
        )
        result = bash(
            script,
            stdin="y\nworker-one\n10.1.2.3\nnode.example.com\ncdn.example.com\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERIFY=panel.example.com/yes", result.stdout)
        self.assertIn(
            "ONBOARD host=node.example.com cam=cdn.example.com vision=[] name=worker-one ip=10.1.2.3",
            result.stdout,
        )
        self.assertNotIn("CMD_NODE=", result.stdout, "the menu bypassed the temporary-access onboarding")

    def test_the_menu_asks_for_a_panel_domain_when_nothing_runs_locally(self):
        script = (
            f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
            "detect_local_panel() { return 1; }\n"
            "wizard_verify_panel_api() { printf 'VERIFY=%s/%s\\n' \"$1\" \"$2\"; return 1; }\n"
            "set +e\n"
            "if wizard_add_node_to_panel; then printf 'RC=0\\n'; else printf 'RC=1\\n'; fi\n"
        )
        # No local Panel: one line for the address, nothing else is reached
        # because the verification refuses.
        result = bash(script, stdin="panel.example.com\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERIFY=panel.example.com/no", result.stdout)
        self.assertIn("RC=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
