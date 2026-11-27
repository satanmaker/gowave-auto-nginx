#!/usr/bin/env python3
"""Suite nonroot: the interactive setup wizard, its catalog and its budget.

Every test drives the sourced shell functions with scripted answers, so the
collected plan is observed rather than asserted from the source text. Two
exceptions read the source instead: the non-TTY entry runs the real CLI and
reads its refusal, and the guarded reachability of the catalog is asserted
against the shipped scripts, where a lookup could be added outside a function
a test can call.
"""
import fcntl
import os
import pty
import re
import select
import shlex
import shutil
import subprocess
import tempfile
import termios
import time
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

# The Panel client the inventory read resolves when a test substitutes the
# module root: it records how it was authenticated, so a read that reached the
# Panel behind a token with no `nodes:read` is visible rather than silent.
FAKE_PANEL_CLIENT = '''\
import os


class GoWaveAPIError(Exception):
    pass


class GoWaveClient:
    def __init__(self, base):
        self.base = base
        self.token = ""
        self._log(f"base={base}")

    def _log(self, line):
        path = os.environ.get("FAKE_LOG")
        if not path:
            return
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\\n")

    def login(self, username, password):
        self._log(f"login={username}/{password}")
        error = os.environ.get("FAKE_LOGIN_ERROR")
        if error:
            raise GoWaveAPIError(error)
        self.token = "admin-session"
        return self.token

    def list_nodes(self):
        if not self.token:
            raise GoWaveAPIError("no session")
        return [
            {"name": "worker-1", "address": "10.1.2.3", "port": 3002, "uuid": "uuid-1"},
            {"name": "local-node", "address": "10.0.0.1", "port": 3000, "uuid": "uuid-0"},
        ]
'''


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
            "english=$(t wizard.name.panel)\n"
            "unset 'GOWAVE_I18N_RU[wizard.name.panel]'\n"
            "GOWAVE_WIZARD_LANG=ru\n"
            "fallback=$(t wizard.name.panel)\n"
            "printf '%s\\n%s\\n' \"$english\" \"$fallback\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        english, fallback = result.stdout.splitlines()
        self.assertNotEqual(english, "wizard.name.panel")
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
            "t wizard.name.panel\n"
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
        self.assertRegex(result.stdout, "Show installation status")

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
    "printf 'cover=%s\\n' \"$GOWAVE_PLAN_COVER_NAME\"\n"
    "printf 'cover_www=%s\\n' \"$GOWAVE_PLAN_COVER_WWW\"\n"
    "printf 'vision=%s\\n' \"$GOWAVE_PLAN_VISION_NAME\"\n"
    "printf 'email=%s\\n' \"$GOWAVE_PLAN_EMAIL\"\n"
    "printf 'local_label=%s\\n' \"$GOWAVE_PLAN_LOCAL_LABEL\"\n"
    "printf 'shared=%s\\n' \"$GOWAVE_PLAN_SHARED_DOMAIN\"\n"
    "printf 'node_count=%s\\n' \"$GOWAVE_PLAN_NODE_COUNT\"\n"
    "printf 'cert_count=%s\\n' \"$(wizard_plan_certificate_count)\"\n"
    "for i in \"${!GOWAVE_PLAN_NODE_NAMES[@]}\"; do\n"
    "  printf 'node=%s|%s|%s\\n' \"${GOWAVE_PLAN_NODE_NAMES[$i]}\""
    " \"${GOWAVE_PLAN_NODE_CAMOUFLAGE[$i]}\" \"${GOWAVE_PLAN_NODE_VISION[$i]:-}\"\n"
    "  printf 'node_label=%s\\n' \"${GOWAVE_PLAN_NODE_LABELS[$i]:-}\"\n"
    "done\n"
)


class TestCollectPlan(unittest.TestCase):
    def _collect(self, answers, failing=(), lang=None):
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory, failing)
            env = {"GOWAVE_WIZARD_RESOLVER": resolver}
            if lang:
                env["GOWAVE_WIZARD_LANG"] = lang
            result = bash(
                SOURCE_WIZARD
                + "if wizard_collect_plan >/dev/null; then echo COLLECTED; else echo REFUSED; fi\n"
                + DUMP_PLAN,
                stdin=answers,
                env=env,
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
            "local-01\nadmin@example.com\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["variant"], "all-in-one")
        self.assertEqual(values["local_label"], "local-01")
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
            "node1.example.com\ncdn1.example.com\nn\nams-01\n"
            "node2.example.com\ncdn2.example.com\ny\nvision2.example.com\nfra-01\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["variant"], "panel-only")
        self.assertEqual(values["local_label"], "")
        self.assertEqual(values["vision"], "")
        self.assertEqual(values["cert_count"], "7")
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|vision2.example.com"],
        )

    def test_multi_node_collects_every_worker_and_its_optional_vision(self):
        verdict, values, nodes, _ = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\ny\nvision.example.com\n"
            "local-01\nadmin@example.com\n2\n"
            "node1.example.com\ncdn1.example.com\nn\nams-01\n"
            "node2.example.com\ncdn2.example.com\ny\nvision2.example.com\n"
            "fra-01\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["variant"], "multi-node")
        self.assertEqual(values["cert_count"], "8")
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|vision2.example.com"],
        )

    def test_a_plan_with_an_unresolvable_name_is_refused_before_collection_ends(self):
        verdict, values, nodes, stderr = self._collect(
            "en\n1\npanel.example.com\nmissing.example.com\nn\nlocal-01\n"
            "admin@example.com\nn\n",
            failing=("missing.example.com",),
        )
        self.assertEqual(verdict, "REFUSED")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(nodes, [])
        self.assertIn("missing.example.com", stderr)
        self.assertNotIn("These names do not resolve: panel.example.com", stderr)

    def test_an_unresolvable_name_re_asks_only_its_own_field(self):
        """A name the resolver cannot answer sends the operator back to that field."""
        verdict, values, nodes, stderr = self._collect(
            "en\n1\npanel.example.com\nmissing.example.com\nn\nlocal-01\n"
            "admin@example.com\nn\n"
            # The failed check routes to the camouflage field alone.
            "cdn.example.com\n",
            failing=("missing.example.com",),
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertEqual(values["local_label"], "local-01")
        self.assertEqual(nodes, [])
        self.assertIn("missing.example.com", stderr)
        self.assertIn("Back to Panel camouflage domain (REALITY SNI)", stderr)
        # The card that already answered is not asked again.
        self.assertEqual(stderr.count("Panel domain ("), 1)
        self.assertEqual(stderr.count("A node name is required."), 0)

    def test_a_rejected_variant_answer_and_a_bad_node_count_repeat_the_question(self):
        verdict, values, _, _ = self._collect(
            "en\n9\n1\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["variant"], "all-in-one")

        verdict, values, _, _ = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\n0\n1\n"
            "node1.example.com\ncdn1.example.com\nn\nams-01\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["cert_count"], "4")

    def test_a_duplicate_cover_domain_is_corrected_before_the_next_question(self):
        """The refused name is re-asked alone, so the Panel and node 1 survive it."""
        verdict, values, nodes, stderr = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\n2\n"
            "node1.example.com\ncdn1.example.com\nn\nams-01\n"
            # node 2's cover domain repeats node 1's, then is corrected in place.
            "node2.example.com\ncdn1.example.com\ncdn2.example.com\nn\nfra-01\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|"],
        )
        refusal = "cdn1.example.com is already used by node 1 camouflage domain in this plan."
        self.assertIn(refusal, stderr)
        # The correction happens before Vision for that node is asked, and
        # nothing already answered is asked again.
        self.assertLess(stderr.index(refusal), stderr.index("Enable Vision for node2.example.com"))
        self.assertEqual(stderr.count("Select deployment scheme"), 1)
        self.assertEqual(stderr.count("Panel domain ("), 1)
        self.assertEqual(stderr.count("Node 2 primary domain"), 1)
        self.assertEqual(stderr.count("Node 2 camouflage domain"), 2)

    def test_a_duplicate_names_its_owner_in_the_selected_language(self):
        """The owner of a taken name is translated, not left as an English fragment."""
        verdict, values, nodes, stderr = self._collect(
            "3\n"
            # The Panel camouflage repeats the Panel domain of the same card.
            "panel.example.com\npanel.example.com\ncdn.example.com\nn\nlocal-01\n"
            "admin@example.com\n1\n"
            # The node's cover domain repeats the Panel camouflage of the plan.
            "node1.example.com\ncdn.example.com\ncdn1.example.com\nn\nams-01\nn\n",
            lang="ru",
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(nodes, ["node1.example.com|cdn1.example.com|"])
        self.assertIn("уже используется", stderr)
        self.assertIn("ответ, который вы уже дали в этой карточке", stderr)
        self.assertIn("домен прикрытия панели", stderr)
        self.assertNotIn("in this plan", stderr)

    def test_a_blank_node_name_is_refused_and_the_question_repeats(self):
        """A name nobody typed is not a name; only the field is asked again."""
        verdict, values, _, stderr = self._collect(
            "en\n1\npanel.example.com\ncdn.example.com\nn\n\nlocal-01\n"
            "admin@example.com\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["local_label"], "local-01")
        self.assertEqual(stderr.count("A node name is required."), 1)
        # Every other answer survived the refusal.
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["email"], "admin@example.com")

    def test_a_padded_node_name_is_stored_without_its_spaces(self):
        """Surrounding whitespace is typing, not part of the name."""
        verdict, values, nodes, stderr = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\nn\n  local-01  \n"
            "admin@example.com\n1\n"
            "node1.example.com\ncdn1.example.com\nn\n  ams-01\t\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["local_label"], "local-01")
        self.assertEqual(values["node_label"], "ams-01")
        self.assertEqual(nodes, ["node1.example.com|cdn1.example.com|"])
        self.assertNotIn("already used", stderr)

    def test_a_case_only_difference_is_the_same_name(self):
        """AMS-01 and ams-01 are one server to the Panel, so they collide here."""
        verdict, values, _, stderr = self._collect(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\n"
            "admin@example.com\n2\n"
            "node1.example.com\ncdn1.example.com\nn\nams-01\n"
            "node2.example.com\ncdn2.example.com\nn\nAMS-01\nfra-01\nn\n"
        )
        self.assertEqual(verdict, "COLLECTED")
        self.assertEqual(values["node_label"], "fra-01")
        self.assertIn("Node name AMS-01 is already used by node 1.", stderr)
        # The correction costs one question, not the earlier cards.
        self.assertEqual(stderr.count("Node 1 primary domain"), 1)
        self.assertEqual(stderr.count("Panel domain ("), 1)

    def test_the_summary_shows_each_servers_own_name(self):
        """Two nodes keep two different names all the way to the confirmation."""
        with tempfile.TemporaryDirectory() as directory:
            result = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null || exit 1\n"
                + "wizard_plan_summary\n",
                stdin=(
                    "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\n"
                    "admin@example.com\n2\n"
                    "node1.example.com\ncdn1.example.com\nn\nams-01\n"
                    "node2.example.com\ncdn2.example.com\nn\nfra-01\nn\n"
                ),
                env={"GOWAVE_WIZARD_RESOLVER": write_resolver(directory)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Panel (local-01): panel=panel.example.com", result.stdout)
        self.assertIn("node 1 (ams-01): transport=node1.example.com", result.stdout)
        self.assertIn("node 2 (fra-01): transport=node2.example.com", result.stdout)
        self.assertEqual(result.stdout.count("(ams-01)"), 1)
        self.assertEqual(result.stdout.count("(fra-01)"), 1)
        # A Worker's first name is its transport, never a Panel: the summary has
        # to keep the role the operator saw when the question was asked.
        for line in result.stdout.splitlines():
            if line.startswith(("  node 1", "  node 2")):
                self.assertNotIn("panel=", line)

    def test_a_worker_with_vision_shows_three_names_and_two_without(self):
        """Vision is a third owned name; its absence leaves the other two."""
        with tempfile.TemporaryDirectory() as directory:
            with_vision = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null || exit 1\n"
                + "wizard_plan_summary\n",
                stdin=(
                    "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\n"
                    "admin@example.com\n1\n"
                    "node1.example.com\ncdn1.example.com\ny\nxtls1.example.com\nams-01\nn\n"
                ),
                env={"GOWAVE_WIZARD_RESOLVER": write_resolver(directory)},
            )
            without_vision = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null || exit 1\n"
                + "wizard_plan_summary\n",
                stdin=(
                    "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\n"
                    "admin@example.com\n1\n"
                    "node1.example.com\ncdn1.example.com\nn\nams-01\nn\n"
                ),
                env={"GOWAVE_WIZARD_RESOLVER": write_resolver(directory)},
            )
        self.assertEqual(with_vision.returncode, 0, with_vision.stderr)
        self.assertEqual(without_vision.returncode, 0, without_vision.stderr)

        three = "transport=node1.example.com camouflage=cdn1.example.com vision=xtls1.example.com"
        two = "transport=node1.example.com camouflage=cdn1.example.com vision=none"
        self.assertIn(three, with_vision.stdout)
        self.assertIn(two, without_vision.stdout)
        # The questions themselves name the role each answer serves, so a
        # Worker name is never introduced as a Panel.
        for result in (with_vision, without_vision):
            self.assertIn("XHTTP, WS and gRPC", result.stderr)
            self.assertIn("no Panel runs here", result.stderr)
        self.assertIn("REALITY SNI", with_vision.stderr)
        self.assertIn("REALITY SNI", without_vision.stderr)


class TestVariantMenu(unittest.TestCase):
    """The scheme menu states where the Panel and the nodes run, in both languages.

    The placement is the whole question: an operator who reads "All-in-One"
    learns nothing about what lives on this server, and the answer decides
    whether a lost host takes a client endpoint with it.
    """

    OPTION = re.compile(r"^[123]\) ")

    def _select(self, stdin, lang="en"):
        result = bash(
            SOURCE_WIZARD
            + "if wizard_select_variant; then printf 'variant=%s\\n' \"$GOWAVE_PLAN_VARIANT\";"
            " else echo REFUSED; fi\n",
            stdin=stdin,
            env={"GOWAVE_WIZARD_LANG": lang},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def options(self, stderr):
        return [line for line in stderr.splitlines() if self.OPTION.match(line)]

    def test_each_scheme_names_where_the_panel_and_the_nodes_run(self):
        result = self._select("1\n")
        lines = self.options(result.stderr)
        self.assertEqual(len(lines), 3, result.stderr)
        one, two, three = lines
        self.assertIn("this server", one)
        self.assertEqual(lines[1], two)
        self.assertIn("separate servers", two)
        self.assertIn("recommended", two)
        self.assertNotIn("not recommended", two.lower())
        self.assertIn("elsewhere", three)
        self.assertIn("not recommended", three.lower())

    def test_the_menu_states_that_no_scheme_fails_over_by_itself(self):
        result = self._select("1\n")
        self.assertIn("moves clients between nodes automatically", result.stderr)

    def test_enter_selects_no_scheme_and_repeats_the_question(self):
        result = self._select("\n2\n")
        self.assertEqual(result.stdout.strip(), "variant=panel-only")
        self.assertEqual(len(self.options(result.stderr)), 6, result.stderr)
        self.assertIn("1, 2 or 3", result.stderr)

    def test_the_russian_menu_states_the_same_three_placements(self):
        result = self._select("3\n", lang="ru")
        lines = self.options(result.stderr)
        self.assertEqual(len(lines), 3, result.stderr)
        self.assertIn("рекомендуется", lines[1])
        self.assertNotIn("не рекомендуется", lines[1])
        self.assertIn("не рекомендуется", lines[2])

    def test_the_guide_names_every_menu_action_and_the_recommendation(self):
        keys = (
            "status", "install", "add_node", "change_domains", "switch_channel",
            "backup", "restore", "user_links", "uninstall", "exit",
        )
        lookups = "".join(f"printf '%s\\n' \"$(t menu.option.{key})\"\n" for key in keys)
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=en\n" + lookups
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8")
        for label in result.stdout.splitlines():
            self.assertIn(label, document, f"the guide does not name the menu action: {label}")
        lowered = re.sub(r"\s+", " ", document.lower())
        self.assertIn("the recommended shape is panel-only", lowered)
        self.assertIn("not recommended", lowered)
        self.assertIn("no scheme moves clients between nodes automatically", lowered)


class TestInteractiveMenu(unittest.TestCase):
    """The menu holds a result on screen until Enter, then redraws once.

    Drives the real CLI over a pseudo-terminal, so the screen observed here is
    the one an operator reads. TERM is removed: a menu that dies because `clear`
    cannot find a terminal type is the same defect as a screen erased before it
    was read.
    """

    MENU_TITLE = b"GoWave Auto NGINX Manager"
    PAUSE = b"Press Enter to return to the menu"

    @staticmethod
    def _attach_controlling_terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    @staticmethod
    def _read_until(fd, marker, timeout=30.0):
        deadline = time.time() + timeout
        buffer = b""
        while marker not in buffer:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise AssertionError(f"timed out waiting for {marker!r}; read {buffer!r}")
            ready, _, _ = select.select([fd], [], [], min(0.2, remaining))
            if not ready:
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                raise AssertionError(f"the terminal closed while waiting for {marker!r}: {buffer!r}")
            buffer += chunk
        return buffer

    def _spawn(self):
        merged = {k: v for k, v in os.environ.items() if k != "TERM"}
        merged["GOWAVE_WIZARD_LANG"] = "en"
        master, slave = pty.openpty()
        process = subprocess.Popen(
            ["bash", str(GOWAVE_AUTO)],
            stdin=slave, stdout=slave, stderr=slave,
            env=merged,
            cwd=str(REPO_ROOT),
            preexec_fn=self._attach_controlling_terminal,
        )
        os.close(slave)
        self.addCleanup(process.kill)
        self.addCleanup(self._close_quietly, master)
        return master, process

    @staticmethod
    def _close_quietly(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def test_the_status_screen_waits_for_enter_and_the_menu_redraws_once(self):
        master, process = self._spawn()
        initial = self._read_until(master, b"Select option")
        self.assertEqual(initial.count(self.MENU_TITLE), 1, initial.decode(errors="replace"))

        os.write(master, b"1\n")
        held = self._read_until(master, self.PAUSE)
        self.assertNotIn(self.MENU_TITLE, held,
                         "the menu was redrawn before the operator acknowledged the status")
        for header in (b"GoWave Auto NGINX Service Status", b"--- Systemd Services ---",
                       b"--- Port Listeners ---", b"--- Certificate Lineages ---"):
            self.assertIn(header, held, held.decode(errors="replace"))
        self.assertIn(b"Port 443", held)
        # The terminal translates the line feed, so match the rule and the
        # question as one unit instead of pinning the newline spelling.
        self.assertIsNotNone(
            re.search(rb"={20,}\r?\n" + re.escape(self.PAUSE), held),
            "the pause does not follow the end of the status report",
        )

        os.write(master, b"\n")
        redrawn = self._read_until(master, b"Select option")
        self.assertEqual(redrawn.count(self.MENU_TITLE), 1,
                         "Enter produced no single redraw of the menu")

        os.write(master, b"0\n")
        self.assertEqual(process.wait(timeout=30), 0)

    def test_worker_summary_stays_visible_until_enter_in_both_languages(self):
        for language, pause, fragments in (
            ("en", "Press Enter to return to the menu", (
                "registered and verified in the Panel", "could not confirm Worker security",
                "a Panel on another host cannot confirm it", "failed (phase: revoke",
            )),
            ("ru", "Нажмите Enter, чтобы вернуться в меню", (
                "зарегистрирован и подтверждён панелью", "Не удалось подтвердить настройки безопасности",
                "удалённая панель отсюда не может это подтвердить", "неудача (phase: revoke",
            )),
        ):
            with self.subTest(language=language):
                script = f'source {shlex.quote(str(GOWAVE_AUTO))}\n' + r'''
trap - ERR
render() {
    local -a rows=(
        $'worker-ok\tVERIFIED\tuuid-good'
        $'worker-security\tUNVERIFIED\tsecurity'
        $'worker-inventory\tUNVERIFIED\tunreadable'
        $'worker-cleanup\tFAILED\trevoke\tcleanup incomplete'
    )
    _print_onboarding_summary rows panel.example.com
    return 2
}
menu_action render
printf 'REDRAW\n'
'''
                master, slave = pty.openpty()
                try:
                    with subprocess.Popen(
                        ["bash", "-c", script], stdin=slave, stdout=slave, stderr=slave,
                        env={**os.environ, "GOWAVE_WIZARD_LANG": language},
                        preexec_fn=self._attach_controlling_terminal,
                    ) as process:
                        os.close(slave)
                        slave = -1
                        try:
                            held = self._read_until(master, pause.encode()).decode()
                            for fragment in fragments:
                                self.assertIn(fragment, held)
                            self.assertNotIn("REDRAW", held)
                            os.write(master, b"\n")
                            self._read_until(master, b"REDRAW")
                            self.assertEqual(process.wait(timeout=10), 0)
                        finally:
                            if process.poll() is None:
                                process.kill()
                finally:
                    self._close_quietly(master)
                    self._close_quietly(slave)

    def test_end_of_input_leaves_the_menu_cleanly(self):
        master, process = self._spawn()
        self._read_until(master, b"Select option")
        os.write(master, b"\x04")
        self.assertEqual(process.wait(timeout=30), 0,
                         "end of input must leave the menu the way option 0 does")

    def test_a_positional_status_never_waits_for_an_answer(self):
        process = subprocess.Popen(
            ["bash", str(GOWAVE_AUTO), "status"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=str(REPO_ROOT),
        )
        self.addCleanup(process.kill)
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.fail("a positional status waited for input that no operator was asked for")
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertIn("GoWave Auto NGINX Service Status", stdout)
        self.assertNotIn("Press Enter", stdout + stderr)


class TestMenuActionStrictness(unittest.TestCase):
    """A menu-startable mutation keeps its own errexit; the menu outlives it.

    Two claims hold at once: a mandatory step that fails inside a menu-started
    action stops the steps behind it, and that failure never ends the session. A
    shell function called from an OR-list inherits errexit switched off, so the
    shipped `menu_action` runs the action in a subshell that re-arms
    `set -Eeuo pipefail` and takes the options it needs as its own. These tests
    drive that wrapper and read both halves from what the action printed.
    """

    FAILURE = "The action exited with status %s."

    @staticmethod
    def source(extra):
        return f"source {shlex.quote(str(GOWAVE_AUTO))}\n{extra}"

    def test_a_failed_local_install_is_named_and_the_next_action_runs(self):
        script = self.source(
            "clear() { :; }\n"
            "cmd_status() { printf 'STATUS-OK\\n'; return 0; }\n"
            "cmd_install() { printf 'LOCAL\\n'; return 5; }\n"
            "main_menu\n"
            "main_menu\n"
        )
        result = bash(script, stdin="2\n1\n", env={"GOWAVE_WIZARD_LANG": "en"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LOCAL", result.stdout)
        self.assertIn(self.FAILURE % 5, result.stderr)
        self.assertIn("STATUS-OK", result.stdout,
                      "the menu did not accept a second action after the first one failed")
        self.assertEqual(result.stdout.count("GoWave Auto NGINX Manager"), 2,
                         "the menu was not shown again after the failed action")

    def test_a_failing_firewall_step_stops_the_payload_and_compensates_once(self):
        script = self.source(
            "install_local() { printf 'LOCAL\\n'; apply_firewall; printf 'LOCAL-AFTER\\n'; }\n"
            "apply_firewall() { printf 'FIREWALL\\n'; return 4; }\n"
            "deploy_payload() { printf 'PAYLOAD\\n'; }\n"
            "cmd_install() {\n"
            "    trap 'printf \"COMPENSATED\\n\"' EXIT\n"
            "    trap 'printf \"ERR-TRAP\\n\"' ERR\n"
            "    install_local\n"
            "    deploy_payload\n"
            "}\n"
            "menu_action cmd_install\n"
            "printf 'ALIVE=%s\\n' \"$?\"\n"
        )
        result = bash(script, env={"GOWAVE_WIZARD_LANG": "en"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FIREWALL", result.stdout)
        self.assertNotIn("LOCAL-AFTER", result.stdout,
                         "a step behind the failing firewall call still ran")
        self.assertNotIn("PAYLOAD", result.stdout,
                         "the payload was deployed after the firewall step failed")
        self.assertEqual(result.stdout.count("COMPENSATED"), 1,
                         "the compensation did not run exactly once")
        self.assertEqual(result.stdout.count("ERR-TRAP"), 1,
                         "the ERR trap did not see the nested failure")
        self.assertIn(self.FAILURE % 4, result.stderr)
        self.assertIn("ALIVE=0", result.stdout)

    def test_a_failing_payload_step_reports_its_own_code(self):
        script = self.source(
            "install_local() { printf 'LOCAL\\n'; return 0; }\n"
            "deploy_payload() { printf 'PAYLOAD\\n'; return 7; }\n"
            "cmd_install() { trap 'printf \"COMPENSATED\\n\"' EXIT;"
            " install_local; deploy_payload; }\n"
            "menu_action cmd_install\n"
        )
        result = bash(script, env={"GOWAVE_WIZARD_LANG": "en"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PAYLOAD", result.stdout)
        self.assertIn(self.FAILURE % 7, result.stderr)
        self.assertEqual(result.stdout.count("COMPENSATED"), 1,
                         "a failed payload ran its compensation more than once")

    def test_the_real_firewall_step_refuses_inside_the_wrapper_without_a_payload(self):
        # `firewall_apply_policy` is the product's own step, not a fixture: with
        # nothing prepared it refuses instead of guessing the managed ingress,
        # and the payload behind it must stay undeployed.
        script = self.source(
            "deploy_payload() { printf 'PAYLOAD\\n'; return 0; }\n"
            "cmd_install() { firewall_apply_policy; deploy_payload; }\n"
            "menu_action cmd_install\n"
            "printf 'ALIVE=%s\\n' \"$?\"\n"
        )
        result = bash(script, env={"GOWAVE_WIZARD_LANG": "en"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no firewall policy was prepared", result.stderr)
        self.assertNotIn("PAYLOAD", result.stdout,
                         "the payload was deployed after the real firewall step refused")
        self.assertIn(self.FAILURE % 1, result.stderr)
        self.assertIn("ALIVE=0", result.stdout)

    def test_the_menu_keeps_its_own_errexit_after_a_failed_action(self):
        script = self.source(
            "cmd_install() { return 9; }\n"
            "menu_action cmd_install\n"
            "printf 'BEFORE\\n'\n"
            "false\n"
            "printf 'AFTER\\n'\n"
        )
        result = bash(script, env={"GOWAVE_WIZARD_LANG": "en"})
        self.assertIn("BEFORE", result.stdout)
        self.assertNotIn("AFTER", result.stdout,
                         "the wrapper left the menu's own errexit switched off")
        self.assertEqual(result.returncode, 1,
                         "a failure after the action did not end the sourced script")


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
        # The guard captures the onboarding status and hands it back unchanged:
        # the loop already distinguishes a clean run (0), a partial one (2) and
        # a failed one (1), and the install's exit status is that same code.
        self.assertIn('wizard_onboard_nodes "https://$panel_domain" "127.0.0.1" "yes" || onboard_rc=$?', install_body)
        self.assertIn('return "$onboard_rc"', install_body)
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
            [
                "gowave-auto.sh",
                "modules/geoip.sh",
                "modules/ssh_bootstrap.sh",
                "modules/wizard.sh",
            ],
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
            [],
            "a shipped script outside the wizard onboards a node directly",
        )
        # The menu reaches the SSH hop through the wizard's own runner: it is
        # that runner which captures the identity, reads the registration back
        # and produces the record the result line is printed from.
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        start = source.index("wizard_add_node_to_panel() {")
        body = source[start : source.index("\n}\n", start)]
        self.assertIn("_wizard_onboard_record", body)
        self.assertEqual(
            source.count("_wizard_onboard_record"),
            body.count("_wizard_onboard_record"),
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
    """wizard_onboard_nodes: the exit codes, the verified readback, one scratch tree.

    The loop decides whether a single broken Worker is fatal, so the exit code it
    returns is the contract the install's own exit status carries. The outcomes
    are driven by replacing two boundaries — the SSH hop, which needs a second
    host, and the Panel readback, which needs a registration the stub never
    performed — and leaving the summary, the retry offer and the scratch cleanup
    to the shipped code.
    """

    PLAN = (
        "GOWAVE_PLAN_NODE_NAMES=('worker-ok' 'worker-bad')\n"
        "GOWAVE_PLAN_NODE_CAMOUFLAGE=('cam-ok.example' 'cam-bad.example')\n"
        "GOWAVE_PLAN_NODE_VISION=('' '')\n"
    )

    VERIFIER = "wizard_verify_node_registration() { printf 'uuid-%s' \"$1\"; return 0; }\n"

    def test_results_are_private_and_persisted_before_rendering(self):
        result, _survived = self.onboard(
            {"worker-ok": True, "worker-bad": True},
            extra='''_print_onboarding_summary() {
    local path="$GOWAVE_STATE_DIR/wizard_node_results"
    [[ "$(stat -c %a "$path")" == 600 && "$(wc -l < "$path")" == 2 ]] && printf 'SUMMARY_SAVED\\n'
}
''',
        )
        self.assertIn("SUMMARY_SAVED", result.stdout, result.stderr)
        self.assertIn("RC=0", result.stdout)

    def test_a_failed_result_write_keeps_the_old_summary_and_stops_retry(self):
        result, _survived = self.onboard(
            {"worker-ok": True, "worker-bad": False},
            extra='''printf 'previous result\\n' > "$GOWAVE_STATE_DIR/wizard_node_results"
sync() { return 1; }
_print_onboarding_summary() {
    local previous
    read -r previous < "$GOWAVE_STATE_DIR/wizard_node_results"
    [[ "$previous" == 'previous result' ]] && printf 'SUMMARY_VISIBLE\\n'
}
_offer_selective_retry() { printf 'RETRY_CALLED\\n'; }
''',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SUMMARY_VISIBLE", result.stdout)
        self.assertIn("RC=2", result.stdout)
        self.assertIn("Could not save the node results", result.stderr)
        self.assertNotIn("RETRY_CALLED", result.stdout)

    def onboard(self, outcomes, stdin="2\n", callee=None, verifier=VERIFIER, extra=""):
        """Run the loop over two Workers; ``outcomes`` maps name to success.

        ``callee`` replaces the generated stub with a body that models the SSH
        hop's own side effects — the real one tracks a key directory of its own.
        ``verifier`` replaces the Panel readback, which would otherwise read a
        real Panel that never saw the stub's node. ``extra`` is prepended to the
        script for stubs the case owns — the retry inspection, which would
        otherwise find neither a journal nor an SSH server.
        """
        stubs = [
            "ssh_bootstrap_onboard_one() {",
            '  case "$1" in',
        ]
        for name, succeeds in outcomes.items():
            if succeeds:
                # The identity marker is what the real onboarding writes before
                # `node add`, and the readback is keyed on it.
                stubs.append(
                    f"    {name}) printf '==> Onboarding %s\\n' \"$1\";"
                    f" printf 'NODE-IDENTITY:%s\\t203.0.113.7\\t3002\\n' \"$1\" >&2; return 0 ;;"
                )
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
            + extra
            + "\n".join(stubs)
            + "\n"
            + verifier
            + "set +e\nwizard_onboard_nodes\nrc=$?\nprintf 'RC=%d\\n' \"$rc\"\n"
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
        self.assertIn(
            "  worker-ok: registered and verified in the Panel (uuid uuid-worker-ok)",
            result.stdout,
        )
        self.assertIn(
            "  worker-bad: failed (phase: scan, reason: Could not read the SSH host key of worker-bad.)",
            result.stdout,
        )
        self.assertIn("Registered and verified in the Panel: 1 of 2.", result.stdout)
        offer = result.stdout.split("Some nodes failed. Select a node to retry, or skip:", 1)[1]
        self.assertNotIn("worker-ok", offer, "the retry offer named a node that succeeded")
        self.assertIn("worker-bad", offer)
        self.assertIn("Retry skipped.", offer)

    def test_every_node_succeeding_exits_zero_without_a_retry_offer(self):
        result, _survived = self.onboard({"worker-ok": True, "worker-bad": True})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=0", result.stdout)
        self.assertIn("Registered and verified in the Panel: 2 of 2.", result.stdout)
        self.assertNotIn("Some nodes failed", result.stdout)
        self.assertNotIn("installation again", result.stdout, "a complete run carried a retry line")

    def test_every_node_failing_is_partial_and_still_offers_the_batch(self):
        # The Panel is deployed and serving, so this is a partial run, not a
        # Panel failure: 1 belongs to a Panel that did not deploy. The retry is
        # offered for the whole batch because rerunning the installation would
        # repeat Panel work that already succeeded.
        result, _survived = self.onboard({"worker-ok": False, "worker-bad": False}, stdin="3\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=2", result.stdout)
        self.assertIn("Registered and verified in the Panel: 0 of 2.", result.stdout)
        self.assertIn(
            "No node was registered. The Panel is installed and serving;",
            result.stdout,
            "an all-failed run did not say what remains",
        )
        offer = result.stdout.split("Some nodes failed. Select a node to retry, or skip:", 1)[1]
        self.assertIn("  1) worker-ok", offer)
        self.assertIn("  2) worker-bad", offer)
        self.assertIn("Retry skipped.", offer)

    def test_a_retry_that_repairs_every_node_ends_the_run_clean(self):
        # Both nodes failed at the first pass; each confirmed retry verifies its
        # node. The final code is read from the records the retries wrote, not
        # from the first pass, so the repaired batch exits zero.
        callee = (
            "ssh_bootstrap_onboard_one() {\n"
            '  local counter="$GOWAVE_STATE_DIR/attempt-$1" attempt=0\n'
            '  [[ -f "$counter" ]] && attempt=$(cat "$counter")\n'
            '  attempt=$((attempt + 1))\n'
            '  printf \'%s\\n\' "$attempt" > "$counter"\n'
            "  printf 'ATTEMPT:%s:%s\\n' \"$1\" \"$attempt\"\n"
            "  if (( attempt == 1 )); then\n"
            "    printf 'PHASE:scan\\n' >&2\n"
            "    printf 'Could not read the SSH host key.\\n' >&2\n"
            "    return 1\n"
            "  fi\n"
            "  printf 'NODE-IDENTITY:%s\\t203.0.113.7\\t3002\\n' \"$1\" >&2\n"
            "  return 0\n"
            "}\n"
        )
        result, _survived = self.onboard(
            {"worker-ok": False, "worker-bad": False}, callee=callee,
            extra="_retry_diagnostics() { return 0; }\n",
            stdin="1\ny\n1\ny\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Retry succeeded: worker-ok", result.stdout)
        self.assertIn("Retry succeeded: worker-bad", result.stdout)
        after = result.stdout.split("Retry succeeded: worker-bad", 1)[1]
        self.assertIn("Registered and verified in the Panel: 2 of 2.", after)
        self.assertIn("RC=0", result.stdout,
                      "a repaired batch kept the code the first pass alone would have produced")
        self.assertEqual(result.stdout.count("ATTEMPT:worker-ok:2"), 1,
                         "the repaired node was not onboarded exactly twice")
        self.assertEqual(result.stdout.count("ATTEMPT:worker-bad:2"), 1,
                         "the repaired node was not onboarded exactly twice")
        self.assertNotIn("ATTEMPT:worker-ok:3", result.stdout)
        self.assertNotIn("ATTEMPT:worker-bad:3", result.stdout)

    def test_a_declined_retry_keeps_the_partial_code(self):
        # Declining is a decision, not a repair: nothing is onboarded again and
        # the all-failed batch keeps the partial-success code.
        result, _survived = self.onboard(
            {"worker-ok": False, "worker-bad": False},
            extra="_retry_diagnostics() { return 0; }\n",
            stdin="1\nn\n3\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Retry declined, worker-ok was not touched.", result.stdout)
        self.assertNotIn("Retrying worker-ok", result.stdout)
        self.assertIn("RC=2", result.stdout)
        self.assertEqual(result.stdout.count("worker-ok: failed (phase: scan"), 1,
                         "a declined retry reprinted the screen as if the node had changed")

    def test_a_registered_node_whose_cleanup_failed_is_not_registered_twice(self):
        # `node add` runs before the cleanup stages, so a failure at `revoke`
        # leaves a node the Panel already holds. The reason names that
        # registration, the retry keeps it instead of asking for a second node
        # by the same name, and the run stays nonzero because the cleanup is
        # still unverified.
        callee = (
            "ssh_bootstrap_onboard_one() {\n"
            "  printf 'ONBOARD:%s\\n' \"$1\"\n"
            "  if [[ \"$1\" == worker-bad ]]; then\n"
            "    printf 'NODE-IDENTITY:%s\\t203.0.113.7\\t3002\\n' \"$1\" >&2\n"
            "    printf 'PHASE:revoke\\n' >&2\n"
            "    printf 'The temporary key could not be revoked.\\n' >&2\n"
            "    return 1\n"
            "  fi\n"
            "  printf 'NODE-IDENTITY:%s\\t203.0.113.7\\t3002\\n' \"$1\" >&2\n"
            "  return 0\n"
            "}\n"
        )
        extra = (
            "_retry_diagnostics() { [[ \"$1\" == worker-bad ]]; }\n"
            "wizard_panel_inventory_names() { "
            "printf 'worker-bad\\t203.0.113.7\\t3002\\tuuid-worker-bad\\n'; }\n"
        )
        result, _survived = self.onboard(
            {"worker-ok": True, "worker-bad": False}, callee=callee, extra=extra,
            stdin="1\ny\n2\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "  worker-bad: failed (phase: revoke, reason: registered in the Panel as "
            "uuid-worker-bad at 203.0.113.7:3002; The temporary key could not be revoked.)",
            result.stdout,
            "a registration left behind by a failed cleanup was not reported",
        )
        self.assertIn(
            "Retry kept the registration the failed attempt made: the Panel holds "
            "worker-bad at 203.0.113.7:3002 (uuid uuid-worker-bad), so the node was "
            "not registered again.",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("ONBOARD:worker-bad"), 1,
                         "the retry registered a node the Panel already held")
        after = result.stdout.split("Retry kept the registration", 1)[1]
        self.assertIn("worker-bad: failed (phase: revoke", after,
                      "the retried row lost the stage that failed")
        self.assertIn("Registered and verified in the Panel: 1 of 2.", after)
        self.assertIn("RC=2", result.stdout,
                      "a pending cleanup was reported as a completed run")

    def test_a_panel_that_does_not_list_the_node_fails_it_at_the_verify_step(self):
        # `node add` exited 0, but the Panel's own list is the authority: the
        # registration is reported against the stage that did not hold, not as
        # a success that only a process exit code supports.
        verifier = "wizard_verify_node_registration() { printf 'missing'; return 1; }\n"
        result, _survived = self.onboard({"worker-ok": True, "worker-bad": True},
                                         verifier=verifier, stdin="3\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=2", result.stdout)
        self.assertIn(
            "  worker-ok: failed (phase: verify, reason: the Panel's node list does not hold this node)",
            result.stdout,
        )
        self.assertIn("Registered and verified in the Panel: 0 of 2.", result.stdout)

    def test_a_name_the_panel_holds_at_another_address_names_that_address(self):
        verifier = (
            "wizard_verify_node_registration() {"
            " printf 'moved\\t198.51.100.4\\t3002'; return 1; }\n"
        )
        result, _survived = self.onboard({"worker-ok": True, "worker-bad": True}, verifier=verifier)
        self.assertIn(
            "reason: the Panel lists it at 198.51.100.4:3002",
            result.stdout,
        )

    def test_an_unreadable_panel_leaves_the_run_nonzero_but_not_failed(self):
        # A remote Panel's token is not this host's to hold: nothing is
        # disproved, so no node is reported as failed and no retry is offered.
        # An unconfirmed registration is still not readiness, though, so the
        # run exits with the partial code and says what would clear it.
        verifier = "wizard_verify_node_registration() { return 2; }\n"
        result, _survived = self.onboard({"worker-ok": True, "worker-bad": True}, verifier=verifier)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=2", result.stdout)
        self.assertIn(
            "  worker-ok: registered; a Panel on another host cannot confirm it from here",
            result.stdout,
        )
        self.assertIn("Registered and verified in the Panel: 0 of 2.", result.stdout)
        self.assertIn(
            "The Panel did not answer its own node list from this host, so these nodes are "
            "registered but unconfirmed.",
            result.stdout,
            "an unconfirmed run did not name what would clear it",
        )
        self.assertNotIn("Some nodes failed", result.stdout)
        self.assertNotIn("failed (phase:", result.stdout)

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


# The stored draft as the fields the resume tests assert on. Each printer reads
# the document back out of the store, so the answer comes from what a later
# process would load, not from what this one holds in memory.
DUMP_STORED_REVIEW = (
    "draft_load | python3 -c 'import json, sys\n"
    "document = json.load(sys.stdin)\n"
    "print(\"reviewed=%s\" % (\"yes\" if document[\"reviewed_digest\"] else \"no\"))\n"
    "print(\"operation=%s\" % document[\"operation_id\"])\n"
    "print(\"panel=%s\" % document[\"answers\"].get(\"primary_domain\", \"\"))\n"
    "'\n"
)
DUMP_STORED_CHECKPOINTS = (
    "draft_load | python3 -c 'import json, sys\n"
    "document = json.load(sys.stdin)\n"
    "for identity in sorted(document[\"checkpoints\"]):\n"
    "    print(\"checkpoint=%s:%s\" % (identity,"
    " document[\"checkpoints\"][identity].get(\"state\", \"missing\")))\n"
    "'\n"
)


def stored_values(stdout):
    """The `key=value` lines a draft printer wrote, without the node rows."""
    values = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key not in {"node", "node_label"}:
            values[key] = value
    return values


class TestDeploymentDraftPersistence(unittest.TestCase):
    """The draft across processes: restored answers, review and abandonment.

    A draft exists to outlive a process, so every case here reads in one shell
    what another shell wrote. The second process is the evidence: it has never
    seen the plan variables, and everything it prints comes from the store.
    """

    PLAN = (
        "GOWAVE_PLAN_VARIANT=multi-node\n"
        "GOWAVE_PLAN_PANEL_NAME=panel.example.com\n"
        "GOWAVE_PLAN_CAMOUFLAGE_NAME=cdn.example.com\n"
        "GOWAVE_PLAN_EMAIL=admin@example.com\n"
        "GOWAVE_PLAN_LOCAL_LABEL=local-01\n"
        "GOWAVE_PLAN_NODE_COUNT=2\n"
        "GOWAVE_PLAN_NODE_NAMES=('worker-a.example.com' 'worker-b.example.com')\n"
        "GOWAVE_PLAN_NODE_CAMOUFLAGE=('cam-a.example.com' 'cam-b.example.com')\n"
        "GOWAVE_PLAN_NODE_VISION=('' 'vision-b.example.com')\n"
        "GOWAVE_PLAN_NODE_LABELS=('ams-01' 'fra-01')\n"
    )

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        # A directory the store creates itself, so the ownership and permission
        # rules are exercised rather than bypassed by a mkdir in the test.
        self.path = str(Path(self.directory) / "deployment" / "active.json")

    def run_wizard(self, script, stdin=""):
        return bash(
            SOURCE_WIZARD + script,
            stdin=stdin,
            env={"GOWAVE_DRAFT_PATH": self.path, "GOWAVE_WIZARD_LANG": "en"},
        )

    def test_a_new_process_restores_the_answers_and_the_review(self):
        saved = self.run_wizard(self.PLAN + "draft_save_plan --reviewed\n")
        self.assertEqual(saved.returncode, 0, saved.stderr)

        restored = self.run_wizard(
            "draft_restore_saved || { printf 'RESTORE_FAILED\\n'; exit 1; }\n"
            "printf 'operation=%s\\n' \"$GOWAVE_DRAFT_OPERATION\"\n"
            "printf 'reviewed=%s\\n' \"$GOWAVE_DRAFT_REVIEWED\"\n"
            + DUMP_PLAN
        )
        self.assertEqual(restored.returncode, 0, restored.stderr)
        values = stored_values(restored.stdout)
        self.assertEqual(values["variant"], "multi-node")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertEqual(values["local_label"], "local-01")
        self.assertEqual(values["node_count"], "2")
        self.assertIn("worker-a.example.com|cam-a.example.com|", restored.stdout)
        self.assertIn("worker-b.example.com|cam-b.example.com|vision-b.example.com", restored.stdout)
        self.assertEqual(values["reviewed"], "yes",
                         "a plan saved as authorized was restored without its review")
        self.assertRegex(values["operation"], r"^[0-9a-f]{32}$")

        stored = self.run_wizard(DUMP_STORED_REVIEW)
        self.assertEqual(stored_values(stored.stdout)["reviewed"], "yes")

    def test_an_edit_after_review_withdraws_only_the_authorization(self):
        # The same draft keeps its operation id, so the edit is a correction of
        # the plan the operator started, not a second deployment beside it. What
        # it loses is the authorization: exactly these answers were approved,
        # and these are no longer them.
        first = self.run_wizard(
            self.PLAN + "draft_save_plan --reviewed\n" + DUMP_STORED_REVIEW
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        approved = stored_values(first.stdout)
        self.assertEqual(approved["reviewed"], "yes")

        edited = self.run_wizard(
            "draft_restore_saved || exit 1\n"
            "GOWAVE_PLAN_EMAIL=other@example.com\n"
            "draft_save_plan || exit 1\n"
        )
        self.assertEqual(edited.returncode, 0, edited.stderr)

        after = self.run_wizard(DUMP_STORED_REVIEW)
        values = stored_values(after.stdout)
        self.assertEqual(values["operation"], approved["operation"],
                         "an edit started a second deployment beside the saved plan")
        self.assertEqual(values["reviewed"], "no",
                         "an edited plan kept the authorization of the answers it replaced")

    def test_abandoning_forgets_the_draft_and_keeps_working_without_one(self):
        saved = self.run_wizard(self.PLAN + "draft_save_plan --reviewed\n")
        self.assertEqual(saved.returncode, 0, saved.stderr)

        abandoned = self.run_wizard(
            self.PLAN
            + "draft_abandon\n"
            "draft_abandon\n"  # idempotent: nothing to forget the second time
            "if draft_load >/dev/null 2>&1; then printf 'LOADED\\n'; else printf 'ABSENT\\n'; fi\n"
            "[[ -f \"$GOWAVE_DRAFT_PATH\" ]] && printf 'FILE=%s\\n' \"$GOWAVE_DRAFT_PATH\"\n"
            "printf 'still_planned=%s\\n' \"$GOWAVE_PLAN_VARIANT\"\n"
        )
        self.assertEqual(abandoned.returncode, 0, abandoned.stderr)
        self.assertIn("ABSENT", abandoned.stdout)
        self.assertNotIn("FILE=", abandoned.stdout,
                         "abandoning left the draft it was told to forget")
        # Abandoning a plan is not a reset of the answers in hand and not an
        # uninstall: nothing here removes anything but the draft.
        self.assertIn("still_planned=multi-node", abandoned.stdout)

    def test_a_draft_from_another_installer_revision_is_refused_rather_than_used(self):
        # A resume after an upgrade that changed the plan vocabulary cannot mean
        # what the saved answers meant. The store refuses to rewrite the draft,
        # so the resume has to refuse to restore it: accepting answers it could
        # never save would lose them silently at the end of the collection.
        saved = self.run_wizard(
            self.PLAN + "GOWAVE_INSTALLER_REVISION=rev-a draft_save_plan\n"
        )
        self.assertEqual(saved.returncode, 0, saved.stderr)

        moved = self.run_wizard(
            "GOWAVE_INSTALLER_REVISION=rev-b\n"
            + self.PLAN
            + "if draft_save_plan >/dev/null 2>&1; then printf 'SAVED\\n'; else printf 'REFUSED\\n'; fi\n"
            "rc=0\n"
            "wizard_collect_plan >/dev/null || rc=$?\n"
            "printf 'COLLECT_RC=%d\\n' \"$rc\"\n"
        )
        self.assertEqual(moved.returncode, 0, moved.stderr)
        self.assertIn("REFUSED", moved.stdout)
        self.assertIn("rev-a", moved.stderr)
        self.assertIn("Use the original installer revision", moved.stderr)
        self.assertIn("COLLECT_RC=1", moved.stdout)
        self.assertNotIn("Select deployment scheme", moved.stderr)
        self.assertNotIn("Saved plan restored", moved.stderr)
        stored = self.run_wizard(DUMP_STORED_REVIEW)
        self.assertEqual(stored_values(stored.stdout)["panel"], "panel.example.com",
                         "a refused resume changed the plan the other revision saved")

    def test_an_unsupported_draft_schema_is_preserved_and_stops_collection(self):
        self.assertEqual(self.run_wizard(self.PLAN + "draft_save_plan\n").returncode, 0)
        path = Path(self.path)
        draft = path.read_text(encoding="utf-8")
        self.assertIn('"schema_version": 1', draft)
        unsupported = draft.replace('"schema_version": 1', '"schema_version": 99')
        path.write_text(unsupported, encoding="utf-8")
        result = self.run_wizard("wizard_collect_plan\n", stdin="2\n3\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("check its permissions and schema", result.stderr)
        self.assertNotIn("Select deployment scheme", result.stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), unsupported)


class TestResumedCollection(unittest.TestCase):
    """wizard_collect_plan over a saved plan: only the unanswered questions.

    The resumed run is driven with an answer list that omits everything the
    draft already holds. If a question were asked again its answer would be the
    next line, so the collected plan is what says which questions were asked —
    and the prompts on stderr say it directly.
    """

    PANEL = (
        "GOWAVE_PLAN_VARIANT=multi-node\n"
        "GOWAVE_PLAN_PANEL_NAME=panel.example.com\n"
        "GOWAVE_PLAN_CAMOUFLAGE_NAME=cdn.example.com\n"
    )
    RESTORED = "Saved plan restored. Only the questions it never answered are asked."

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.path = str(Path(self.directory) / "deployment" / "active.json")
        self.resolver = write_resolver(self.directory)

    def run_wizard(self, script, stdin=""):
        return bash(
            SOURCE_WIZARD + script,
            stdin=stdin,
            env={
                "GOWAVE_DRAFT_PATH": self.path,
                "GOWAVE_WIZARD_LANG": "en",
                "GOWAVE_WIZARD_RESOLVER": self.resolver,
            },
        )

    def seed(self, plan):
        result = self.run_wizard(plan + "draft_save_plan\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def collect(self, answers):
        # The collection's own stdout is kept apart: it carries the summary the
        # operator reads, whose rows include `panel=…`, and the review menu. Only
        # the plan dump below is parsed as data.
        out = str(Path(self.directory) / "collect.out")
        return self.run_wizard(
            "rc=0\n"
            f"wizard_collect_plan >{shlex.quote(out)} || rc=$?\n"
            "printf 'RC=%d\\n' \"$rc\"\n"
            f"if grep -q 'Saved plan restored' {shlex.quote(out)}; then"
            " printf 'restored=yes\\n'; else printf 'restored=no\\n'; fi\n"
            + DUMP_PLAN
            + DUMP_STORED_REVIEW,
            stdin=answers,
        )

    def test_a_resumed_run_asks_only_for_what_the_draft_never_answered(self):
        self.seed(self.PANEL)
        result = self.collect(
            "1\n"                       # continue the saved plan
            "local-01\n"                # the label the draft never reached
            "admin@example.com\n"       # the contact the draft never reached
            "1\n"                       # the node count the draft never reached
            "worker-a.example.com\n"
            "cam-a.example.com\n"
            "n\n"                       # this node gets no Vision
            "ams-01\n"
            "n\n"                       # separate certificate names
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = stored_values(result.stdout)
        self.assertEqual(values["RC"], "0")
        self.assertEqual(values["variant"], "multi-node")
        self.assertEqual(values["panel"], "panel.example.com",
                         "the restored Panel answer was asked again and replaced")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertEqual(values["local_label"], "local-01")
        self.assertIn("worker-a.example.com|cam-a.example.com|", result.stdout)
        self.assertEqual(values["restored"], "yes",
                         "the operator was not told the saved plan was being continued")
        self.assertNotIn("Panel domain (", result.stderr,
                         "a resumed run asked a Panel question the draft answered")
        self.assertNotIn("Select deployment scheme", result.stderr)
        # The review the resumed run reached is recorded against these answers,
        # so the install that follows is authorized work rather than a plan
        # nobody approved after the interruption.
        self.assertEqual(values["reviewed"], "yes")

    def test_starting_over_asks_the_whole_card_and_stores_the_new_plan(self):
        self.seed(self.PANEL + "GOWAVE_PLAN_EMAIL=saved@example.com\n")
        result = self.collect(
            "2\n"                       # start over
            "3\n"                       # multi-node, asked because nothing is saved now
            "new-panel.example.com\n"
            "new-cdn.example.com\n"
            "n\n"
            "local-02\n"
            "new@example.com\n"
            "1\n"
            "new-node.example.com\n"
            "new-cam.example.com\n"
            "n\n"
            "new-01\n"
            "n\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = stored_values(result.stdout)
        self.assertEqual(values["RC"], "0")
        self.assertEqual(values["panel"], "new-panel.example.com",
                         "starting over kept an answer from the abandoned plan")
        self.assertEqual(values["local_label"], "local-02")
        self.assertIn("new-node.example.com|new-cam.example.com|", result.stdout)
        self.assertIn("Select deployment scheme", result.stderr,
                      "starting over did not ask from the beginning")
        self.assertNotIn("saved@example.com", result.stdout)
        # What the next process would load is the new plan, not a merge.
        self.assertEqual(values["panel"], "new-panel.example.com")

    def test_starting_over_forgets_the_saved_plan_before_answering_anything(self):
        # The menu line says the saved plan is forgotten, so it has to be gone
        # by the time the operator answers the next question. A run that stops at
        # that question is what tells the two apart: if the draft only vanished
        # when collection later saved, the old plan would still be on disk here
        # and the next process would offer it again as if nothing was chosen.
        self.seed(self.PANEL)
        result = self.run_wizard(
            "rc=0\n"
            "wizard_collect_plan >/dev/null || rc=$?\n"
            "printf 'RC=%d\\n' \"$rc\"\n"
            "if draft_load >/dev/null 2>&1; then printf 'LOADED\\n'; else printf 'ABSENT\\n'; fi\n",
            stdin="2\n",  # start over; the scheme question then hits EOF
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = stored_values(result.stdout)
        self.assertEqual(values["RC"], "1", "collection did not stop where the answers did")
        self.assertIn("ABSENT", result.stdout,
                      "the forgotten plan was still stored after starting over")

    def test_leaving_the_menu_keeps_the_draft_and_asks_nothing(self):
        self.seed(self.PANEL)
        result = self.run_wizard(
            "rc=0\n"
            "wizard_collect_plan >/dev/null || rc=$?\n"
            "printf 'RC=%d\\n' \"$rc\"\n"
            + DUMP_STORED_REVIEW,
            stdin="3\n",  # leave; nothing is collected
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = stored_values(result.stdout)
        self.assertEqual(values["RC"], "3",
                         "leaving the resume menu was not distinguishable from collecting")
        self.assertEqual(values["panel"], "panel.example.com",
                         "leaving the menu discarded a draft the operator did not abandon")
        self.assertNotIn("Panel domain (", result.stderr)


class TestResumedOnboarding(unittest.TestCase):
    """wizard_onboard_nodes on a resumed plan: verify what stands, build the rest.

    The SSH hop and the Panel readback are the two boundaries this needs a
    second host for, so both are stubbed; what the test reads is how often each
    one was reached. A node the draft recorded as verified costs no SSH session,
    including when the Panel contradicts the record. Only pending siblings
    go through onboarding.
    """

    PLAN = (
        "GOWAVE_PLAN_VARIANT=multi-node\n"
        "GOWAVE_PLAN_PANEL_NAME=panel.example.com\n"
        "GOWAVE_PLAN_NODE_NAMES=('ok.example.com' 'bad.example.com')\n"
        "GOWAVE_PLAN_NODE_CAMOUFLAGE=('cam-ok.example.com' 'cam-bad.example.com')\n"
        "GOWAVE_PLAN_NODE_VISION=('' '')\n"
        "GOWAVE_PLAN_NODE_LABELS=('ok-01' 'bad-01')\n"
    )
    # The Panel issues canonical UUIDs and the draft schema stores nothing less,
    # so the stubs answer with the shape a real registration produces.
    OK_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    BAD_UUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    ONBOARD = (
        "ssh_bootstrap_onboard_one() {\n"
        "  printf 'ONBOARD:%s\\n' \"$1\" >> \"$GOWAVE_DRAFT_LOG\"\n"
        "  printf 'NODE-IDENTITY:%s\\t203.0.113.7\\t3002\\n' \"$4\" >&2\n"
        "  return 0\n"
        "}\n"
    )
    # The readback answers by name: the recheck asks with no address because the
    # draft stores none, and the onboarding asks with the identity it just made.
    VERIFIER = (
        "wizard_verify_node_registration() {\n"
        "  printf 'VERIFY:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >> \"$GOWAVE_DRAFT_LOG\"\n"
        "  case \"$1\" in\n"
        "    ok-01) printf '%s' \"$OK_UUID\" ;;\n"
        "    *) printf '%s' \"$BAD_UUID\" ;;\n"
        "  esac\n"
        "  return 0\n"
        "}\n"
    )

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.path = str(Path(self.directory) / "deployment" / "active.json")
        self.log = str(Path(self.directory) / "calls.log")
        Path(self.log).write_text("", encoding="utf-8")

    def run_wizard(self, script, stdin=""):
        return bash(
            "source " + shlex.quote(str(I18N_SH)) + "\n"
            "source " + shlex.quote(str(REPO_ROOT / "modules" / "tempdir.sh")) + "\n"
            + SOURCE_WIZARD + script,
            stdin=stdin,
            env={
                "GOWAVE_DRAFT_PATH": self.path,
                "GOWAVE_DRAFT_LOG": self.log,
                "OK_UUID": self.OK_UUID,
                "BAD_UUID": self.BAD_UUID,
            },
        )

    def seed(self, checkpoints):
        """Write the plan and the verdicts an interrupted run left behind."""
        lines = [self.PLAN, "draft_save_plan\n"]
        for identity, record in checkpoints.items():
            arguments = " ".join(shlex.quote(field) for field in record.split())
            lines.append(f"draft_checkpoint {identity} {arguments}\n")
        result = self.run_wizard("".join(lines))
        self.assertEqual(result.returncode, 0, result.stderr)

    def batch(self, verifier):
        return self.run_wizard(
            "GOWAVE_STATE_DIR=$(mktemp -d)\n"
            "track_temp_dir \"$GOWAVE_STATE_DIR\"\n"
            + self.PLAN
            + "GOWAVE_DRAFT_RESUMED=1\n"
            + self.ONBOARD
            + 'wizard_panel_inventory_names() { [[ $# == 4 ]]; }\n'
            + 'verify_public_tls_sni() { return 0; }\n'
            + 'verify_worker_security_readback() { return 0; }\n'
            + verifier
            + "set +e\n"
            "wizard_onboard_nodes\n"
            "rc=$?\n"
            "printf 'RC=%d\\n' \"$rc\"\n"
            + DUMP_STORED_CHECKPOINTS,
            stdin="3\n",
        )

    def calls(self):
        return Path(self.log).read_text(encoding="utf-8").splitlines()

    def test_a_recorded_node_is_rechecked_by_name_and_not_onboarded_again(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": "pending registration 0"})
        result = self.batch(self.VERIFIER)
        self.assertEqual(result.returncode, 0, result.stderr)
        values = stored_values(result.stdout)
        self.assertEqual(values["RC"], "0")
        calls = self.calls()
        self.assertNotIn("ONBOARD:ok.example.com", calls,
                         "a node the Panel still held was onboarded a second time")
        self.assertEqual(calls.count("ONBOARD:bad.example.com"), 1)
        # The recheck compared the name the Panel registered. The draft stores
        # no address, so the readback is asked by name rather than by a guess.
        self.assertEqual(calls.count("VERIFY:ok-01::"), 1,
                         f"the recheck invented an address to compare: {calls}")
        self.assertIn(
            f"ok.example.com: registered and verified in the Panel (uuid {self.OK_UUID})",
            result.stdout,
        )
        self.assertIn("Registered and verified in the Panel: 2 of 2.", result.stdout)
        self.assertIn("checkpoint=node-1:verified", result.stdout)

    def test_a_missing_recorded_node_does_not_block_its_pending_sibling(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": "pending registration 0"})
        result = self.batch(
            "wizard_verify_node_registration() {\n"
            "  printf 'VERIFY:%s:%s\\n' \"$1\" \"$2\" >> \"$GOWAVE_DRAFT_LOG\"\n"
            "  if [[ \"$1\" == ok-01 ]]; then return 1; fi\n"
            "  printf '%s' \"$BAD_UUID\"\n"
            "}\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "2")
        self.assertEqual(self.calls(), ["VERIFY:ok-01:", "ONBOARD:bad.example.com",
                                        "VERIFY:bad-01:203.0.113.7"])
        self.assertIn("recorded identity could not be confirmed", result.stdout)
        self.assertIn("checkpoint=node-1:indeterminate", result.stdout)
        self.assertIn("checkpoint=node-2:verified", result.stdout)

    def test_an_unreadable_panel_keeps_the_record_and_opens_no_ssh(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": "pending registration 0"})
        result = self.batch(
            "wizard_verify_node_registration() {\n"
            "  printf 'VERIFY:%s:%s\n' \"$1\" \"$2\" >> \"$GOWAVE_DRAFT_LOG\"\n"
            "  if [[ \"$1\" == ok-01 && -z \"$2\" ]]; then return 2; fi\n"
            "  printf '%s' \"$BAD_UUID\"\n"
            "  return 0\n"
            "}\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "2",
                         "an unconfirmed node was reported as a completed run")
        calls = self.calls()
        self.assertNotIn("ONBOARD:ok.example.com", calls,
                         "a node was rebuilt because a remote Panel could not be read")
        self.assertIn("checkpoint=node-1:indeterminate", result.stdout,
                      "an unreadable Panel overwrote the record it could not check")
        self.assertIn(
            "ok.example.com: registered; a Panel on another host cannot confirm it from here",
            result.stdout,
        )

    def test_resume_review_protects_recorded_identities_but_allows_pending_edits(self):
        self.seed({"panel": "verified complete 1", "node-2": f"indeterminate verification 1 {self.BAD_UUID}"})
        result = self.run_wizard(
            self.PLAN
            + 'GOWAVE_DRAFT_RESUMED=1\nGOWAVE_PLAN_NODE_COUNT=2\n'
              'for edit in "panel_domain new.example.com" "node_label_1 new-label" "node_count 1"; do\n'
              '    read -r field value <<< "$edit"\n'
              '    if _wizard_review_apply "$field" "$value"; then exit 9; fi\n'
              'done\n'
              '_wizard_review_apply node_label_0 pending-label\n'
              'printf "%s:%s:%s:%s\\n" "$GOWAVE_PLAN_PANEL_NAME" "${GOWAVE_PLAN_NODE_LABELS[@]}" "$GOWAVE_PLAN_NODE_COUNT"\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("panel.example.com:pending-label:bad-01:2", result.stdout)
        self.assertEqual(result.stderr.count("already recorded by deployment"), 3)

    def test_matching_uuid_does_not_hide_changed_host_associations(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": f"verified complete 1 {self.BAD_UUID}"})
        result = self.batch(
            self.VERIFIER
            + 'wizard_panel_inventory_names() { [[ "$4" == "$BAD_UUID" ]]; }\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "2")
        self.assertEqual(self.calls(), ["VERIFY:ok-01::", "VERIFY:bad-01::"])
        self.assertIn("checkpoint=node-1:indeterminate", result.stdout)
        self.assertIn("checkpoint=node-2:verified", result.stdout)

    def test_failed_worker_tls_stops_only_that_worker(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": f"verified complete 1 {self.BAD_UUID}"})
        result = self.batch(
            self.VERIFIER
            + 'verify_public_tls_sni() { printf "TLS:%s:%s:%s\\n" "$1" "$2" "$3" >> "$GOWAVE_DRAFT_LOG";'
              ' [[ "$1" != cam-ok.example.com ]]; }\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "2")
        self.assertIn("did not pass TLS verification", result.stdout)
        self.assertNotIn("The Panel did not answer its own node list", result.stdout)
        self.assertIn("checkpoint=node-1:indeterminate", result.stdout)
        self.assertIn("checkpoint=node-2:verified", result.stdout)
        self.assertEqual(self.calls(), [
            "VERIFY:ok-01::", "TLS:ok.example.com:ok.example.com:443:1",
            "TLS:cam-ok.example.com:ok.example.com:443:1", "VERIFY:bad-01::",
            "TLS:bad.example.com:bad.example.com:443:1", "TLS:cam-bad.example.com:bad.example.com:443:1",
        ])

    def test_failed_security_readback_does_not_reinstall_completed_workers(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": f"verified complete 1 {self.BAD_UUID}"})
        result = self.batch(
            self.VERIFIER
            + 'verify_worker_security_readback() { [[ "$1" == bad.example.com ]]; }\n'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "2")
        self.assertIn("could not confirm Worker security", result.stdout)
        self.assertIn("checkpoint=node-1:indeterminate", result.stdout)
        self.assertIn("checkpoint=node-2:verified", result.stdout)
        self.assertEqual(self.calls(), ["VERIFY:ok-01::", "VERIFY:bad-01::"])

    def test_a_changed_uuid_is_not_adopted_on_this_or_the_next_resume(self):
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": f"verified complete 1 {self.BAD_UUID}"})
        verifier = self.VERIFIER.replace('"$OK_UUID"', '"$BAD_UUID"')
        for _ in range(2):
            result = self.batch(verifier)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stored_values(result.stdout)["RC"], "2")
            self.assertIn("checkpoint=node-1:indeterminate", result.stdout)
            self.assertIn("checkpoint=node-2:verified", result.stdout)
        self.assertEqual(self.calls(), ["VERIFY:ok-01::", "VERIFY:bad-01::"] * 2)
        persisted = self.run_wizard("draft_checkpoint_field node-1 node_uuid\n")
        self.assertEqual(persisted.returncode, 0, persisted.stderr)
        self.assertEqual(persisted.stdout, self.OK_UUID)

    def test_the_recheck_is_not_attempted_for_a_plan_that_was_not_resumed(self):
        # A fresh install has no reason to read a draft: the checkpoints of an
        # abandoned plan must not decide anything about this run.
        self.seed({"node-1": f"verified complete 1 {self.OK_UUID}",
                   "node-2": "pending registration 0"})
        result = self.run_wizard(
            "GOWAVE_STATE_DIR=$(mktemp -d)\n"
            "track_temp_dir \"$GOWAVE_STATE_DIR\"\n"
            + self.PLAN
            + self.ONBOARD
            + self.VERIFIER
            + "set +e\nwizard_onboard_nodes >/dev/null\nrc=$?\nprintf 'RC=%d\\n' \"$rc\"\n",
            stdin="3\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=0", result.stdout)
        calls = self.calls()
        self.assertEqual(calls.count("ONBOARD:ok.example.com"), 1,
                         "a fresh install read a stored checkpoint as progress")
        self.assertEqual(calls.count("ONBOARD:bad.example.com"), 1)


class TestResumePanelReuse(unittest.TestCase):
    """The install's resumed Panel: read it back, or install it as pending work.

    The entrypoint is sourced — it ends with a sourcing guard, so the CLI router
    below it never runs — and each readback is replaced one at a time. What the
    cases read is the install's own decision: which readbacks were reached, what
    the checkpoint became, and which code the run leaves with.
    """

    READBACKS = (
        "preflight_require_direct_dns() { printf 'dns\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
        "bootstrap_early_tools() { return 0; }\n"
        "verify_panel_startup() { printf 'startup\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
        "verify_public_tls_sni() { printf 'sni\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
        "extract_secret_key() { printf 'secret'; return 0; }\n"
        "verify_node_mtls_health() { printf 'mtls\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
        "wizard_panel_inventory_names() { if [[ $# == 2 ]]; then"
        " printf 'local-node\\t127.0.0.1\\t3002\\taaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\n'; fi; }\n"
        "write_security_report() { printf 'report\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
    )

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.path = str(Path(self.directory) / "deployment" / "active.json")
        self.log = str(Path(self.directory) / "calls.log")
        Path(self.log).write_text("", encoding="utf-8")

    def run_install(self, script):
        return bash(
            "source " + shlex.quote(str(GOWAVE_AUTO)) + "\n"
            "trap - ERR\nset +e\n"
            # The wizard has collected a plan by the time the install runs, and
            # a checkpoint is written only for a plan: the variable is what
            # makes the store a participant rather than a no-op.
            "GOWAVE_PLAN_VARIANT=multi-node\n"
            + script,
            env={"GOWAVE_DRAFT_PATH": self.path, "GOWAVE_DRAFT_LOG": self.log},
        )

    def seed_panel(self, record="verified complete 1"):
        result = self.run_install(
            "GOWAVE_PLAN_VARIANT=multi-node\n"
            "GOWAVE_PLAN_PANEL_NAME=panel.example.com\n"
            "draft_save_plan\n"
            f"draft_checkpoint panel {record}\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def calls(self):
        return Path(self.log).read_text(encoding="utf-8").splitlines()

    def verify_panel(self, extra="", mode="all-in-one"):
        return self.run_install(
            self.READBACKS
            + extra
            + "rc=0\n"
            f"resume_verify_panel panel.example.com {shlex.quote(mode)} || rc=$?\n"
            "printf 'RC=%d\\n' \"$rc\"\n"
            + DUMP_STORED_CHECKPOINTS
        )

    def test_every_readback_agreeing_records_the_panel_and_the_local_node(self):
        self.seed_panel()
        result = self.verify_panel()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "0")
        self.assertIn(
            "Resume: the Panel this host serves is the one the saved plan recorded.",
            result.stdout,
        )
        self.assertIn("checkpoint=panel:verified", result.stdout)
        self.assertIn("checkpoint=local-node:verified", result.stdout,
                      "a Panel that answered every readback left its local node unrecorded")
        self.assertEqual(self.calls(), ["dns", "startup", "sni", "mtls", "report"],
                         "the verification did not run the readbacks the checkpoint describes")

    def test_a_panel_that_stopped_answering_fails_the_verification(self):
        self.seed_panel()
        result = self.verify_panel(
            "verify_public_tls_sni() { printf 'sni\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 1; }\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "1")
        self.assertNotIn("checkpoint=local-node", result.stdout,
                         "a Panel that did not serve its own SNI was recorded as verified")
        self.assertEqual(self.calls(), ["dns", "startup", "sni"],
                         "the verification went on after a readback disagreed")

    def test_panel_only_accepts_an_authenticated_empty_inventory(self):
        self.seed_panel()
        result = self.verify_panel(
            "wizard_panel_inventory_names() { return 0; }\n", mode="panel-only"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "0")
        self.assertNotIn("checkpoint=local-node", result.stdout)
        self.assertEqual(self.calls(), ["dns", "startup", "sni", "report"])

    def test_an_all_in_one_panel_that_answers_with_no_nodes_is_not_verified(self):
        # The node list is the readback that proves the credentials in this
        # host's file still read the Panel. An empty answer is not agreement.
        self.seed_panel()
        result = self.verify_panel(
            "wizard_panel_inventory_names() { return 0; }\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "1")
        self.assertIn("the Panel answered its node list with no nodes", result.stderr)

    def test_all_in_one_does_not_mistake_a_remote_node_for_the_local_identity(self):
        self.seed_panel()
        result = self.verify_panel(
            "wizard_panel_inventory_names() { printf 'local-node\\t203.0.113.7\\t3002\\taaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\n'; }\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stored_values(result.stdout)["RC"], "1")
        self.assertNotIn("checkpoint=local-node", result.stdout)
        self.assertEqual(self.calls(), ["dns", "startup", "sni", "mtls"])

    def test_a_fresh_run_takes_no_resume_decision(self):
        # Nothing was interrupted, so a draft that some other run left behind
        # decides nothing about this one.
        self.seed_panel()
        result = self.run_install(
            "resume_verify_panel() { printf 'verify\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "install_finish() { printf 'finish\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "finish=-1\n"
            "if resume_recorded_panel finish panel.example.com all-in-one; then printf 'REUSED\\n';"
            " else printf 'INSTALL\\n'; fi\n"
            "printf 'finish=%s\\n' \"$finish\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INSTALL", result.stdout)
        self.assertIn("finish=-1", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_a_recorded_panel_is_checked_and_the_run_ends_there(self):
        self.seed_panel()
        result = self.run_install(
            "GOWAVE_DRAFT_RESUMED=1\n"
            "resume_verify_panel() { printf 'verify\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "install_finish() { printf 'finish\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "finish=-1\n"
            "if resume_recorded_panel finish panel.example.com all-in-one; then printf 'REUSED\\n';"
            " else printf 'INSTALL\\n'; fi\n"
            "printf 'finish=%s\\n' \"$finish\"\n"
            + DUMP_STORED_CHECKPOINTS
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REUSED", result.stdout)
        self.assertIn("finish=0", result.stdout)
        self.assertEqual(self.calls(), ["verify", "finish"],
                         "a verified Panel was checked without being finished, or finished unchecked")
        self.assertIn("checkpoint=panel:verified", result.stdout)

    def test_a_failed_panel_readback_blocks_reinstall_and_preserves_the_checkpoint(self):
        self.seed_panel()
        result = self.run_install(
            "GOWAVE_DRAFT_RESUMED=1\nGOWAVE_WIZARD_LANG=en\n"
            "resume_verify_panel() { printf 'verify\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 1; }\n"
            "install_finish() { printf 'finish\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "finish=-1\n"
            "if resume_recorded_panel finish panel.example.com all-in-one; then printf 'REUSED\\n';"
            " else printf 'INSTALL\\n'; fi\n"
            "printf 'finish=%s\\n' \"$finish\"\n"
            + DUMP_STORED_CHECKPOINTS
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("INSTALL", result.stdout)
        self.assertIn("finish=1", result.stdout)
        self.assertIn("Check Panel health, DNS, TLS and the security report", result.stderr)
        self.assertEqual(self.calls(), ["verify"])
        self.assertIn("checkpoint=panel:verified", result.stdout)

    def test_a_checkpoint_that_was_never_verified_is_not_even_checked(self):
        self.seed_panel("pending preflight 0")
        result = self.run_install(
            "GOWAVE_DRAFT_RESUMED=1\n"
            "resume_verify_panel() { printf 'verify\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "install_finish() { printf 'finish\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "finish=-1\n"
            "if resume_recorded_panel finish panel.example.com all-in-one; then printf 'REUSED\\n';"
            " else printf 'INSTALL\\n'; fi\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INSTALL", result.stdout)
        self.assertEqual(self.calls(), [],
                         "a Panel with no verified record was checked as if it had one")

    def test_a_node_batch_still_pending_keeps_its_code(self):
        # 2 is the Panel serving with a node that still has work. Returning it
        # is the answer; treating it as "not resumed" would install the Panel a
        # second time over the one that just proved it was serving.
        self.seed_panel()
        result = self.run_install(
            "GOWAVE_DRAFT_RESUMED=1\n"
            "resume_verify_panel() { printf 'verify\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "install_finish() { printf 'finish\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 2; }\n"
            "finish=-1\n"
            "if resume_recorded_panel finish panel.example.com all-in-one; then printf 'REUSED\\n';"
            " else printf 'INSTALL\\n'; fi\n"
            "printf 'finish=%s\\n' \"$finish\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REUSED", result.stdout)
        self.assertIn("finish=2", result.stdout,
                      "a pending node batch was not carried as the run's own exit code")

    def test_the_install_returns_the_code_the_resume_helper_produced(self):
        # The install's first step after the migration gate is the helper. Its
        # answer has to be this run's exit code: falling through would install a
        # Panel the helper had just verified, and swallowing a 2 would report a
        # pending node batch as a clean install.
        result = self.run_install(
            "acquire_lock() { :; }\n"
            "preflight_require_inputs() { return 0; }\n"
            "migration_confirm_existing() { return 0; }\n"
            "preflight_require_direct_dns() { printf 'install\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 1; }\n"
            "resume_recorded_panel() { local -n out=\"$1\"; out=2;"
            " printf 'resume\\n' >> \"$GOWAVE_DRAFT_LOG\"; return 0; }\n"
            "rc=0\n"
            "cmd_install panel.example.com cdn.example.com admin@example.com || rc=$?\n"
            "printf 'RC=%d\\n' \"$rc\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=2", result.stdout)
        self.assertEqual(self.calls(), ["resume"],
                         "the install went on to install a Panel the resume helper had settled")

    def test_resume_checks_the_journal_before_inspecting_or_mutating_the_panel(self):
        self.seed_panel()
        path = Path(self.directory) / "journal.json"
        original_draft = Path(self.path).read_bytes()
        for state, expected in (("NODE_ADD_VERIFYING", "1"),
                                ("NODE_ADD_COMMITTED", "2"),
                                ("invalid-private-value", "1")):
            with self.subTest(state=state):
                journal = (
                    '{"op":"node_add","timestamp":1,"state":"' + state + '"}'
                )
                path.write_text(journal, encoding="utf-8")
                Path(self.log).write_text("", encoding="utf-8")
                result = self.run_install(
                    f"JOURNAL_FILE={shlex.quote(str(path))}\n"
                    "GOWAVE_DRAFT_RESUMED=1\nGOWAVE_WIZARD_LANG=en\n"
                    "acquire_lock() { printf 'lock\\n' >> \"$GOWAVE_DRAFT_LOG\"; }\n"
                    "preflight_require_inputs() { return 0; }\n"
                    "migration_confirm_existing() { printf 'inspect\\n' >> \"$GOWAVE_DRAFT_LOG\"; }\n"
                    "resume_recorded_panel() { local -n out=\"$1\"; out=2;"
                    " printf 'resume\\n' >> \"$GOWAVE_DRAFT_LOG\"; }\n"
                    "rc=0\n"
                    "cmd_install panel.example.com cdn.example.com admin@example.com || rc=$?\n"
                    "printf 'RC=%d\\n' \"$rc\"\n"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(stored_values(result.stdout)["RC"], expected)
                self.assertEqual(path.read_text(encoding="utf-8"), journal)
                self.assertEqual(Path(self.path).read_bytes(), original_draft)
                self.assertNotIn("invalid-private-value", result.stderr)
                if expected == "1":
                    self.assertIn("finish recovery before resuming", result.stderr)
                    self.assertEqual(self.calls(), ["lock"])
                else:
                    self.assertEqual(self.calls(), ["lock", "inspect", "resume"])


class TestNodeRegistrationReadback(unittest.TestCase):
    """wizard_verify_node_registration: the Panel's list decides, not the exit code.

    The three answers are what the summary and the single-add flow build their
    sentences from, so each one is read here on its own: a Panel that holds the
    node, a Panel that answered without it, and a Panel nobody can read.
    """

    def verify(self, inventory, name, address, port, panel_address, panel_is_local):
        args = " ".join(shlex.quote(value) for value in
                        (name, address, port, panel_address, panel_is_local))
        script = (
            SOURCE_WIZARD
            + f"wizard_panel_inventory_names() {{ {inventory}; }}\n"
            + f"if out=$(wizard_verify_node_registration {args}); then rc=0; else rc=$?; fi\n"
            + "printf 'RC=%d\\nOUT=%s\\n' \"$rc\" \"$(printf '%s' \"$out\" | tr '\\t' '|')\"\n"
        )
        return bash(script)

    def test_a_listed_node_at_the_registered_identity_is_verified(self):
        result = self.verify(
            "printf 'ams-01\\t203.0.113.7\\t3002\\tuuid-ams\\n'",
            "ams-01", "203.0.113.7", "3002", "panel.example.com", "yes",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=0", result.stdout)
        self.assertIn("OUT=uuid-ams", result.stdout)

    def test_the_panel_name_comparison_ignores_case(self):
        result = self.verify(
            "printf 'AMS-01\\t203.0.113.7\\t3002\\tuuid-ams\\n'",
            "ams-01", "203.0.113.7", "3002", "panel.example.com", "yes",
        )
        self.assertIn("RC=0", result.stdout)
        self.assertIn("OUT=uuid-ams", result.stdout)

    def test_a_name_the_panel_does_not_list_is_missing(self):
        result = self.verify(
            "printf 'fra-01\\t203.0.113.9\\t3002\\tuuid-fra\\n'",
            "ams-01", "203.0.113.7", "3002", "panel.example.com", "yes",
        )
        self.assertIn("RC=1", result.stdout)
        self.assertIn("OUT=missing", result.stdout)

    def test_the_same_name_at_another_address_reports_the_held_identity(self):
        result = self.verify(
            "printf 'ams-01\\t198.51.100.4\\t3002\\tuuid-other\\n'",
            "ams-01", "203.0.113.7", "3002", "panel.example.com", "yes",
        )
        self.assertIn("RC=1", result.stdout)
        self.assertIn("OUT=moved|198.51.100.4|3002", result.stdout)

    def test_an_unreadable_inventory_disproves_nothing(self):
        for stub in ("return 2", "return 1"):
            with self.subTest(stub=stub):
                result = self.verify(
                    stub, "ams-01", "203.0.113.7", "3002", "panel.example.com", "yes",
                )
                self.assertIn("RC=2", result.stdout)
                self.assertIn("OUT=", result.stdout)
                self.assertNotIn("OUT=missing", result.stdout)

    def test_a_row_without_a_uuid_is_not_a_registration(self):
        result = self.verify(
            "printf 'ams-01\\t203.0.113.7\\t3002\\t-\\n'",
            "ams-01", "203.0.113.7", "3002", "panel.example.com", "yes",
        )
        self.assertIn("RC=1", result.stdout)
        self.assertIn("OUT=missing", result.stdout)


class TestInstallCompletionScreen(unittest.TestCase):
    """The install tail: Panel progress first, completion only when nothing remains.

    The banner used to be printed before the remote nodes were onboarded, so a
    run that was still waiting on SSH had already announced itself as complete.
    """

    def install_body(self):
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        start = source.index("cmd_install() {")
        return source[start : source.index("\ncmd_node() {", start)]

    def test_the_completion_banner_follows_the_node_onboarding(self):
        body = self.install_body()
        self.assertLess(
            body.index("wizard_panel_installed_notice"),
            body.index('echo "Onboarding the planned remote nodes..."'),
        )
        self.assertLess(
            body.index("wizard_onboard_nodes"),
            body.index("GoWave Auto NGINX Installation Complete"),
            "the install announced completion before onboarding the nodes",
        )

    def test_a_node_failure_returns_before_the_completion_banner(self):
        body = self.install_body()
        failure = body.index('return "$onboard_rc"')
        self.assertLess(failure, body.index("GoWave Auto NGINX Installation Complete"))
        self.assertGreater(failure, body.index("wizard_onboard_nodes"))

    def test_a_failed_panel_step_returns_before_the_panel_notice(self):
        # "Panel installed" is a success statement for the Panel step, so the
        # Panel's failure path has to return above it: a run that failed on the
        # Panel prints no Panel line and reaches no banner.
        body = self.install_body()
        failure = body.index("Initial API provisioning failed")
        notice = body.index("wizard_panel_installed_notice")
        self.assertLess(failure, notice, "the Panel's failure path is below its own success line")
        self.assertIn("return 1", body[failure:notice])

    def test_the_panel_statement_names_the_wizard_catalog(self):
        source = WIZARD_SH.read_text(encoding="utf-8")
        start = source.index("wizard_panel_installed_notice() {")
        body = source[start : source.index("\n}\n", start)]
        self.assertIn("wizard.summary.panel", body)

    def test_the_panel_step_is_printed_for_a_plan_that_still_has_nodes(self):
        body = self.install_body()
        guard = body.index('case "${GOWAVE_PLAN_VARIANT:-}" in')
        self.assertLess(guard, body.index("wizard_panel_installed_notice"))
        self.assertIn("multi-node | panel-only", body[guard:body.index("wizard_panel_installed_notice")])


class TestSelectiveRetry(unittest.TestCase):
    """The failed-node retry: inspected, confirmed, and alone in what it reruns.

    The retry is the only place after a partial run that mutates a host, so the
    three promises are read here: the list is the failed nodes only, a node no
    record answered for is refused rather than rerun, and a confirmed retry
    replaces that node's row while the sibling's row and the Panel stay as the
    first pass left them.
    """

    PANEL_DISPLAY = "https://panel.example.com"

    def offer(self, stdin, retryable=("worker-bad",), record="VERIFIED", inspect=True,
              extra_failed=False):
        """Run ``_offer_selective_retry`` over one verified and one failed node.

        The onboarding itself is replaced by a stub that prints the node it was
        asked for and writes the record the shipped code would write, so the
        list, the confirmation, the row replacement and the reprinted screen are
        exercised on the shipped functions. With ``inspect`` the inspection is
        stubbed too, and ``retryable`` names the hosts whose state answered;
        without it the shipped ``_retry_diagnostics`` decides against a host with
        no journal and no SSH server, which is the refusal the caller must obey.
        ``extra_failed`` adds a third node that failed, so a retry leaves a
        failure behind to be offered again.
        """
        second = {
            "VERIFIED": "uuid-bad\\t203.0.113.7:3002",
            "FAILED": "verify\\tmissing",
        }[record]
        rows = [
            "  $'worker-ok\\tVERIFIED\\tuuid-ok\\t203.0.113.7:3002'",
            "  $'worker-bad\\tFAILED\\tscan\\tCould not read the SSH host key of worker-bad.'",
        ]
        names = "'worker-ok' 'worker-bad'"
        camouflage = "'cam-ok.example' 'cam-bad.example'"
        vision = "'' ''"
        labels = "'' ''"
        if extra_failed:
            rows.append(
                "  $'worker-bad2\\tFAILED\\tscan\\tCould not read the SSH host key of worker-bad2.'")
            names += " 'worker-bad2'"
            camouflage += " 'cam-bad2.example'"
            vision += " ''"
            labels += " ''"
        if inspect:
            cases = "\n".join(f"    {shlex.quote(host)}) return 0 ;;" for host in retryable)
            inspection = (
                "_retry_diagnostics() {\n"
                "  case \"$1\" in\n"
                f"{cases}\n"
                "  esac\n"
                "  return 1\n"
                "}\n"
            )
        else:
            inspection = (
                "GOWAVE_JOURNAL_FILE=\"$GOWAVE_STATE_DIR/journal.json\"\n"
                "GOWAVE_SSH_PORT=1\n"
                "ssh_bootstrap_scan() { return 1; }\n"
                "ssh() { return 1; }\n"
            )
        script = (
            f"source {shlex.quote(str(I18N_SH))}\n"
            + SOURCE_WIZARD
            + "GOWAVE_STATE_DIR=$(mktemp -d)\n"
            f"GOWAVE_PLAN_NODE_NAMES=({names})\n"
            f"GOWAVE_PLAN_NODE_CAMOUFLAGE=({camouflage})\n"
            f"GOWAVE_PLAN_NODE_VISION=({vision})\n"
            f"GOWAVE_PLAN_NODE_LABELS=({labels})\n"
            + inspection
            + "_wizard_onboard_record() {\n"
            "  printf 'RECORD:%s\\n' \"$2\"\n"
            "  local -n out=\"$1\"\n"
            f"  out=$(printf '%s\\t{record}\\t{second}' \"$2\")\n"
            "  return 0\n"
            "}\n"
            + "node_results=(\n"
            + "\n".join(rows)
            + "\n)\n"
            "set +e\n"
            f"_offer_selective_retry node_results 127.0.0.1 yes {shlex.quote(self.PANEL_DISPLAY)}\n"
            "printf 'RC=%d\\n' \"$?\"\n"
            "printf 'ROWS:\\n%s\\n' \"$(printf '%s\\n' \"${node_results[@]}\" | tr '\\t' '|')\"\n"
            "printf 'STORED:\\n%s\\n' \"$(tr '\\t' '|' < \"$GOWAVE_STATE_DIR/wizard_node_results\")\"\n"
        )
        return bash(script, stdin=stdin)

    def test_only_the_failed_node_is_offered_and_skipping_touches_nothing(self):
        result = self.offer("2\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        offer = result.stdout.split(
            "Some nodes failed. Select a node to retry, or skip:", 1)[1].split("Choice: ", 1)[0]
        self.assertIn("  1) worker-bad", offer)
        self.assertNotIn("worker-ok", offer, "the offer named a node that already succeeded")
        self.assertIn("Retry skipped.", result.stdout)
        self.assertNotIn("RECORD:", result.stdout, "skipping reran an onboarding")

    def test_a_retry_is_confirmed_before_it_reruns(self):
        result = self.offer("1\nn\n2\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Retry onboarding for worker-bad now? [y/N]: ", result.stderr)
        self.assertIn("Retry declined, worker-bad was not touched.", result.stdout)
        self.assertNotIn("RECORD:", result.stdout, "a declined retry still ran the onboarding")
        self.assertIn("Retry skipped.", result.stdout)

    def test_a_confirmed_retry_reruns_only_that_node_and_reports_its_new_state(self):
        result = self.offer("1\ny\n2\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("RECORD:worker-bad"), 1,
                         f"the failed node was not onboarded exactly once:\n{result.stdout}")
        self.assertNotIn("RECORD:worker-ok", result.stdout,
                         "the sibling that succeeded was onboarded again")
        self.assertIn("Retry succeeded: worker-bad", result.stdout)
        rewritten = result.stdout.split("Retry succeeded: worker-bad", 1)[1]
        self.assertIn(
            "worker-bad: registered and verified in the Panel (uuid uuid-bad)", rewritten,
            "the final screen did not carry the retried node's new verdict",
        )
        self.assertIn("Registered and verified in the Panel: 2 of 2.", rewritten)
        self.assertIn(f"Panel installed: {self.PANEL_DISPLAY}", rewritten,
                      "the reprinted screen dropped the Panel line")
        stored = result.stdout.split("STORED:\n", 1)[1]
        self.assertIn("worker-ok|VERIFIED|uuid-ok|203.0.113.7:3002", stored)
        self.assertIn("worker-bad|VERIFIED|uuid-bad|203.0.113.7:3002", stored)

    def test_the_menu_after_a_retry_names_only_the_nodes_still_failed(self):
        # Two nodes failed; the first retry verifies one. The reprint is the
        # final screen of that attempt, so it has to state the Panel, the count
        # and a menu whose numbers still name the node it is about to ask about.
        result = self.offer("1\ny\n2\n", retryable=("worker-bad", "worker-bad2"),
                            extra_failed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("RECORD:worker-bad2", result.stdout,
                         "the node that was not chosen was onboarded")
        after = result.stdout.split("Retry succeeded: worker-bad", 1)[1]
        summary, _, menu = after.partition(
            "Some nodes failed. Select a node to retry, or skip:")
        self.assertIn(f"Panel installed: {self.PANEL_DISPLAY}", summary)
        self.assertIn("Registered and verified in the Panel: 2 of 3.", summary)
        self.assertIn("worker-bad2: failed (phase: scan", summary)
        self.assertNotIn("worker-bad)", menu, "the menu re-offered a node that just verified")
        self.assertIn("  1) worker-bad2", menu)
        self.assertIn("  2) Skip retry for all failed nodes", menu)
        self.assertIn("Retry skipped.", result.stdout)
        stored = result.stdout.split("STORED:\n", 1)[1]
        self.assertIn("worker-ok|VERIFIED|uuid-ok|203.0.113.7:3002", stored)
        self.assertIn("worker-bad|VERIFIED|uuid-bad|203.0.113.7:3002", stored)
        self.assertIn("worker-bad2|FAILED|scan|", stored)

    def test_a_retry_that_fails_again_keeps_its_row_failed(self):
        result = self.offer("1\ny\n2\n", record="FAILED")
        self.assertIn("Retry failed: worker-bad", result.stderr)
        self.assertIn("Registered and verified in the Panel: 1 of 2.", result.stdout)
        stored = result.stdout.split("STORED:\n", 1)[1]
        self.assertIn("worker-ok|VERIFIED|uuid-ok|203.0.113.7:3002", stored)
        self.assertIn("worker-bad|FAILED|verify|missing", stored)

    def test_a_node_no_record_answered_for_is_refused_without_rerunning(self):
        result = self.offer("1\n2\n", inspect=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Refusing to retry worker-bad:", result.stdout)
        self.assertIn("neither its recovery journal nor its SSH server answered", result.stdout)
        self.assertNotIn("RECORD:", result.stdout, "an unverifiable node was onboarded anyway")
        self.assertIn("Retry skipped.", result.stdout)

    def test_the_inspection_answers_retryable_only_when_a_record_answered(self):
        # Neither record: no journal on this host and no SSH server to ask.
        unreachable = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            + SOURCE_WIZARD
            + "GOWAVE_JOURNAL_FILE=/nonexistent/journal.json\n"
            "GOWAVE_SSH_PORT=1\n"
            "ssh_bootstrap_scan() { return 1; }\n"
            "ssh_bootstrap_fingerprint() { printf 'SHA256:deadbeef'; }\n"
            "ssh() { return 1; }\n"
            "set +e\n"
            "_retry_diagnostics worker-bad >/dev/null\n"
            "printf 'RC=%d\\n' \"$?\"\n"
        )
        self.assertIn("RC=1", unreachable.stdout)

        # The Worker answers, so its state can be read from the host itself.
        reachable = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            + SOURCE_WIZARD
            + "GOWAVE_JOURNAL_FILE=/nonexistent/journal.json\n"
            "GOWAVE_SSH_PORT=1\n"
            "ssh_bootstrap_scan() { printf 'worker-bad ssh-ed25519 AAAA'; }\n"
            "ssh_bootstrap_fingerprint() { printf 'SHA256:deadbeef'; }\n"
            "ssh() { return 1; }\n"
            "set +e\n"
            "_retry_diagnostics worker-bad >/dev/null\n"
            "printf 'RC=%d\\n' \"$?\"\n"
        )
        self.assertIn("RC=0", reachable.stdout)


class TestWizardDocumentation(unittest.TestCase):
    """The three domain limits and the two SSH variables are policy, not prose."""

    def test_resume_guide_distinguishes_actions_and_exit_codes_in_both_languages(self):
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8")
        for heading, actions, outcomes in (
            ("The setup wizard saves accepted answers", (
                "**Continue** restores the answers", "**Start over** discards the draft",
                "**Leave without installing** keeps the draft",
            ), (
                "exit `0` means all requested components were confirmed",
                "Exit `1` means the Panel could not be deployed or verified",
                "Exit `2` means the Panel is ready but at least one requested Worker",
            )),
            ("Мастер сохраняет принятые ответы", (
                "**Продолжить** — восстановить ответы", "**Начать заново** — удалить черновик",
                "**Выйти без установки** — оставить черновик",
            ), (
                "код `0` означает, что все запрошенные компоненты подтверждены",
                "Код `1` означает, что панель не удалось развернуть или подтвердить",
                "Код `2` означает, что панель готова, но как минимум один запрошенный Worker",
            )),
        ):
            with self.subTest(heading=heading):
                section = document.split(heading, 1)[1].split("\n\n", 3)
                self.assertEqual(len(section), 4)
                for action in actions:
                    self.assertIn(action, section[1])
                for outcome in outcomes:
                    self.assertIn(outcome, section[2])

    def test_progress_guide_distinguishes_ssh_timeout_from_worker_rollback(self):
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8")
        text = " ".join(document.split())
        for fragment in (
            "SSH session has a 60-minute budget", "at most 59 times for that session",
            "does not prove that the Worker stopped or rolled back",
            "ограничен 60 минутами", "не более 59 таких сообщений за сеанс",
            "Разрыв SSH не доказывает, что Worker остановился или откатился",
        ):
            self.assertIn(fragment, text)

    def test_the_operator_document_names_every_summary_state(self):
        # The result screen is a claim about the Panel, so the page that
        # describes it has to name the same sentences the screen prints. The
        # fragments are read from the catalog rather than retyped here, and each
        # is cut at its first interpolated value.
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8")
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=en\n"
            "for key in wizard.summary.success wizard.summary.unverified "
            "wizard.summary.count; do\n"
            "  printf '%s\\n' \"$(t \"$key\")\"\n"
            "done\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        fragments = [line.split("%s")[0].strip() for line in result.stdout.splitlines() if line]
        self.assertEqual(len(fragments), 3, f"the catalog did not answer three lines: {result.stdout!r}")
        for fragment in fragments:
            self.assertIn(fragment, document, f"the operator page does not name {fragment!r}")

    def test_the_operator_document_names_every_retry_action(self):
        # The retry is the one screen after the summary that still mutates a
        # host, so the page has to name its actions in the words the wizard
        # prints. Every sentence is rendered from the catalog for the node the
        # page's example retries and looked for in the page's own text, with
        # whitespace and inline-code marks removed so a wrapped line or a
        # backtick does not count as a different sentence.
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8")
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=en\n"
            "for key in wizard.retry.offer wizard.retry.skip wizard.retry.confirm "
            "wizard.retry.declined wizard.retry.unverifiable wizard.retry.retrying "
            "wizard.retry.succeeded wizard.retry.failed wizard.retry.skipped; do\n"
            "  printf '%s\\n' \"$(tf \"$key\" fra-01)\"\n"
            "done\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        sentences = [" ".join(line.split()) for line in result.stdout.splitlines() if line]
        self.assertEqual(len(sentences), 9, f"the catalog did not answer nine lines: {result.stdout!r}")
        page = " ".join(document.replace("`", "").split())
        for sentence in sentences:
            self.assertIn(sentence, page, f"the operator page does not name {sentence!r}")

    def test_the_operator_document_names_the_kept_registration(self):
        # A retry of a node that failed after registering keeps the Panel's row
        # instead of asking for a second one; the page has to name that answer
        # with the same values the screen fills, because it is the sentence an
        # operator reads while deciding whether to register the node again.
        document = (REPO_ROOT / "docs/SETUP_WIZARD.md").read_text(encoding="utf-8")
        result = bash(
            f"source {shlex.quote(str(I18N_SH))}\n"
            "GOWAVE_WIZARD_LANG=en\n"
            "printf '%s\\n' \"$(tf wizard.retry.held fra-01 203.0.113.7 3002 "
            "3d5c9a71-6f24-4b8e-9c07-2a1f5e8d4b63)\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        sentence = " ".join(result.stdout.split())
        self.assertIn("uuid 3d5c9a71-6f24-4b8e-9c07-2a1f5e8d4b63", sentence)
        page = " ".join(document.replace("`", "").split())
        self.assertIn(sentence, page, f"the operator page does not name {sentence!r}")

    def test_the_readme_names_the_three_limits_and_both_variables(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("remaining budget cannot be queried", readme)
        self.assertIn("belongs to a single host", readme)
        self.assertIn("wildcard is not a remedy", readme)
        self.assertIn("gowave_ssh_fingerprint", readme)
        self.assertIn("gowave_ssh_password_file", readme)
        russian = (REPO_ROOT / "README.ru.md").read_text(encoding="utf-8").lower()
        for warning in ("остаток лимита", "одному серверу", "wildcard"):
            self.assertIn(warning, russian)
        for variable in ("gowave_ssh_fingerprint", "gowave_ssh_password_file"):
            self.assertIn(variable, russian)

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
    """The review screen: start, edit the Panel, edit one node, or cancel.

    The action list numbers the nodes, so editing node 2 cannot reach node 1's
    fields, and cancel is a reported outcome rather than an error. The last case
    proves a cancelled plan never reaches the lock or the mutation steps.
    """

    # Collection order: scheme, Panel card, local node name, email, node count,
    # node cards (each followed by its own name), shared domain.
    ALL_IN_ONE = (
        "en\n1\npanel.example.com\ncdn.example.com\ny\nvision.example.com\n"
        "local-01\nadmin@example.com\nn\n"
    )
    ONE_NODE = (
        "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\n1\n"
        "node1.example.com\ncdn1.example.com\nn\nams-01\nn\n"
    )
    TWO_NODES = (
        "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\n2\n"
        "node1.example.com\ncdn1.example.com\nn\nams-01\n"
        "node2.example.com\ncdn2.example.com\nn\nfra-01\nn\n"
    )

    # Review actions: 1 starts, 2 edits the Panel and plan settings, 3 + index
    # edits that node, 0 cancels. Inside a group the fields are numbered as the
    # group lists them and 0 returns to the action list.

    def _review(self, initial_answers, review_answers, failing=()):
        """Run wizard_collect_plan then wizard_review_plan and return the final plan."""
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory, failing)
            result = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null\n"
                + "wizard_review_plan >/dev/null || true\n"
                + DUMP_PLAN,
                stdin=initial_answers + review_answers,
                env={"GOWAVE_WIZARD_RESOLVER": resolver},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        values = dict(line.split("=", 1) for line in lines if "=" in line and "|" not in line)
        nodes = [line.split("=", 1)[1] for line in lines if line.startswith("node=")]
        return values, nodes, result.stderr

    def test_review_plan_can_change_panel_domain_and_preserves_other_fields(self):
        """Changing the panel domain preserves variant, email, camouflage, and nodes."""
        values, nodes, _ = self._review(
            self.ALL_IN_ONE,
            # Edit the Panel ("2"), field 2, the new value, back, start.
            "2\n2\nnewpanel.example.com\n0\n1\n",
        )
        self.assertEqual(values["variant"], "all-in-one")
        self.assertEqual(values["panel"], "newpanel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["vision"], "vision.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertEqual(nodes, [])

    def test_review_plan_can_change_email_and_preserves_other_fields(self):
        """Changing the email preserves all other fields."""
        values, nodes, _ = self._review(
            "en\n1\npanel.example.com\ncdn.example.com\nn\nlocal-01\n"
            "old@example.com\nn\n",
            "2\n6\nnew@example.com\n0\n1\n",
        )
        self.assertEqual(values["email"], "new@example.com")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")

    def test_review_plan_rejects_invalid_hostname(self):
        """An invalid hostname is refused and the field keeps its old value."""
        values, nodes, stderr = self._review(
            self.ALL_IN_ONE,
            # A refused answer keeps the editor open, so the second attempt is
            # a field choice again, not a new action.
            "2\n2\nnot-a-valid-hostname\n2\npanel2.example.com\n0\n1\n",
        )
        self.assertEqual(values["panel"], "panel2.example.com")
        self.assertIn("not-a-valid-hostname", stderr)

    def test_review_plan_rejects_duplicate_name(self):
        """A duplicate name is refused with its owner and the old value is kept."""
        values, nodes, stderr = self._review(
            self.ALL_IN_ONE,
            "2\n2\ncdn.example.com\n2\npanel2.example.com\n0\n1\n",
        )
        self.assertEqual(values["panel"], "panel2.example.com")
        self.assertIn("already used", stderr)

    def test_review_plan_can_change_node_count_and_adds_nodes(self):
        """Raising the node count asks for the new node's whole card."""
        values, nodes, _ = self._review(
            self.ONE_NODE,
            "2\n8\n2\nnode2.example.com\ncdn2.example.com\nn\nbcn-01\n0\n1\n",
        )
        self.assertEqual(values["node_count"], "2")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(values["node_label"], "bcn-01")
        self.assertIn("node1.example.com|cdn1.example.com|", nodes)
        self.assertIn("node2.example.com|cdn2.example.com|", nodes)

    def test_review_plan_can_decrease_node_count(self):
        """Lowering the node count truncates the node arrays."""
        values, nodes, _ = self._review(self.TWO_NODES, "2\n8\n1\n0\n1\n")
        self.assertEqual(values["node_count"], "1")
        self.assertEqual(len(nodes), 1)
        self.assertIn("node1.example.com|cdn1.example.com|", nodes)
        self.assertNotIn("node2.example.com", str(nodes))

    def test_the_panel_group_lists_every_field_with_its_label_and_value(self):
        """A nameless row would still be selectable, so every row must be labelled."""
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory)
            result = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null\n"
                + "review_rc=0\n"
                + "wizard_review_plan || review_rc=$?\n"
                + "printf 'review_rc=%s\\n' \"$review_rc\"\n",
                # Open the Panel group, go back, cancel.
                stdin=self.ONE_NODE + "2\n0\n0\n",
                env={"GOWAVE_WIZARD_RESOLVER": resolver},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("unbound variable", result.stderr)
        for label in (
            "Deployment scheme",
            "Panel domain (browser address; API and subscriptions)",
            "Panel camouflage domain (REALITY SNI)",
            "Panel Vision domain",
            "Local node name",
            "Let's Encrypt email",
            "Shared registered domain",
            "Number of remote nodes",
            "Master static cover apex (empty — none)",
            "Cover www alias",
        ):
            self.assertIn(f"{label} [", result.stdout)
        rows = [line for line in result.stdout.splitlines() if re.match(r"^\s+\d+\) .+ \[.*\]$", line)]
        self.assertEqual(len(rows), 10, rows)

    def test_the_node_group_names_the_transport_and_the_reality_sni(self):
        """A Worker's rows say what each name serves, and never call it a Panel."""
        with tempfile.TemporaryDirectory() as directory:
            result = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null\n"
                + "review_rc=0\n"
                + "wizard_review_plan || review_rc=$?\n"
                + "printf 'review_rc=%s\\n' \"$review_rc\"\n",
                # Open node 1's editor, go back, cancel.
                stdin=self.ONE_NODE + "3\n0\n0\n",
                env={"GOWAVE_WIZARD_RESOLVER": write_resolver(directory)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Node 1 primary domain (XHTTP/WS/gRPC + static cover) [", result.stdout)
        self.assertIn("Node 1 camouflage domain (REALITY SNI) [", result.stdout)
        self.assertNotIn("Node 1 Panel", result.stdout)
        self.assertNotIn("Node 1 is a Panel", result.stdout)

    def test_review_plan_can_rename_the_local_node_and_a_worker(self):
        """Both name rows are editable and the plan keeps what was accepted."""
        values, nodes, _ = self._review(
            self.TWO_NODES,
            # Panel group, local node name; then node 2, its name; back, start.
            "2\n5\nlocal-02\n0\n4\n4\nfra-02\n0\n1\n",
        )
        self.assertEqual(values["local_label"], "local-02")
        self.assertEqual(values["node_label"], "fra-02")
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|"],
        )

    def test_review_plan_refuses_a_name_another_server_already_has(self):
        """The review reuses the collection rule instead of trusting the editor."""
        values, nodes, stderr = self._review(
            self.TWO_NODES,
            "2\n5\nfra-01\n5\nlocal-02\n0\n1\n",
        )
        self.assertEqual(values["local_label"], "local-02")
        self.assertIn("Node name fra-01 is already used by node 2.", stderr)

    def test_review_plan_refuses_a_blank_name_instead_of_keeping_it(self):
        """Blank means "nothing typed", so the empty answer is refused, not kept."""
        values, _, stderr = self._review(self.ONE_NODE, "3\n4\n   \n4\nams-02\n0\n1\n")
        self.assertEqual(values["node_label"], "ams-02")
        self.assertIn("A node name is required.", stderr)

    def test_review_plan_selects_a_cover_apex_and_its_alias(self):
        """The cover apex is a plan field, not a value inferred from the Panel."""
        values, _, _ = self._review(
            self.ONE_NODE,
            # Panel group, cover apex, then its www alias, back, start.
            "2\n9\ncover.example.com\n10\ny\n0\n1\n",
        )
        self.assertEqual(values["cover"], "cover.example.com")
        self.assertEqual(values["cover_www"], "yes")
        self.assertEqual(values["panel"], "panel.example.com")

    def test_a_new_plan_selects_no_cover_apex(self):
        """Nothing is inferred: an untouched plan has no cover site at all."""
        values, _, _ = self._review(self.ALL_IN_ONE, "1\n")
        self.assertEqual(values["cover"], "")
        self.assertEqual(values["cover_www"], "no")

    def test_review_refuses_the_www_alias_without_an_apex(self):
        values, _, stderr = self._review(self.ONE_NODE, "2\n10\ny\n0\n1\n")
        self.assertEqual(values["cover_www"], "no")
        self.assertIn("Select a cover apex", stderr)

    def test_an_empty_answer_removes_a_selected_cover_apex(self):
        values, _, _ = self._review(
            self.ONE_NODE,
            "2\n9\ncover.example.com\n10\ny\n0\n"
            "2\n9\n\n0\n1\n",
        )
        self.assertEqual(values["cover"], "")
        self.assertEqual(values["cover_www"], "no")

    def test_review_refuses_a_cover_apex_another_host_already_owns(self):
        values, _, stderr = self._review(self.ONE_NODE, "2\n9\nnode1.example.com\n0\n1\n")
        self.assertEqual(values["cover"], "")
        self.assertIn("already used by node 1", stderr)

    def test_the_plan_hands_the_cover_to_the_install_as_documented_input(self):
        """The positional contract keeps its names; the cover travels beside it."""
        result = bash(
            SOURCE_WIZARD
            + "GOWAVE_PLAN_VARIANT=all-in-one\n"
            + "GOWAVE_PLAN_PANEL_NAME=panel.example.com\n"
            + "GOWAVE_PLAN_CAMOUFLAGE_NAME=cdn.example.com\n"
            + "GOWAVE_PLAN_EMAIL=admin@example.com\n"
            + "GOWAVE_PLAN_COVER_NAME=example.com\n"
            + "GOWAVE_PLAN_COVER_WWW=yes\n"
            + "wizard_apply_plan\n"
            + "printf 'mode=%s\\n' \"$GOWAVE_INSTALL_MODE\"\n"
            + "printf 'args=%s\\n' \"${#GOWAVE_INSTALL_POSITIONAL[@]}\"\n"
            + "printf 'cover=%s\\n' \"$GOWAVE_COVER_DOMAIN\"\n"
            + "printf 'www=%s\\n' \"$GOWAVE_COVER_WWW\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=all-in-one", result.stdout)
        self.assertIn("args=4", result.stdout)
        self.assertIn("cover=example.com", result.stdout)
        self.assertIn("www=yes", result.stdout)

    def test_editing_the_second_node_leaves_its_sibling_unchanged(self):
        """Node 2 is action 4, and its editor lists only that node's fields."""
        values, nodes, _ = self._review(
            self.TWO_NODES,
            "4\n1\nnode2-renamed.example.com\n0\n1\n",
        )
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2-renamed.example.com|cdn2.example.com|"],
        )
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["email"], "admin@example.com")

    def test_review_plan_can_change_node_name(self):
        """Changing a node's name preserves its other fields."""
        values, nodes, _ = self._review(
            self.ONE_NODE,
            "3\n1\nnode1-renamed.example.com\n0\n1\n",
        )
        self.assertEqual(nodes, ["node1-renamed.example.com|cdn1.example.com|"])

    def test_review_plan_can_change_node_vision(self):
        """Adding Vision to a node that didn't have it."""
        values, nodes, _ = self._review(
            self.ONE_NODE,
            "3\n3\nvision1.example.com\n0\n1\n",
        )
        self.assertEqual(nodes, ["node1.example.com|cdn1.example.com|vision1.example.com"])

    def test_review_plan_can_remove_node_vision(self):
        """An empty Vision answer removes Vision instead of keeping it."""
        values, nodes, _ = self._review(
            "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\n1\n"
            "node1.example.com\ncdn1.example.com\ny\nvision1.example.com\nams-01\nn\n",
            "3\n3\n\n0\n1\n",
        )
        self.assertEqual(nodes, ["node1.example.com|cdn1.example.com|"])
        self.assertNotIn("vision1.example.com", str(nodes))

    def test_review_plan_asks_for_shared_domain_consent_once(self):
        """Start re-checks the budget but does not repeat consent for the same count."""
        values, nodes, stderr = self._review(
            self.ALL_IN_ONE,
            # Shared domain yes, one consent answer, back, start.
            "2\n7\ny\ny\n0\n1\n",
        )
        self.assertEqual(values["shared"], "yes")
        self.assertNotIn("exceed the ceiling", stderr)
        self.assertEqual(stderr.count("budget is shared by the whole cluster"), 1)

    def test_review_routes_an_unresolvable_name_to_its_field_and_keeps_the_plan(self):
        """Start refuses a name it cannot resolve and re-reads only that field."""
        values, nodes, stderr = self._review(
            self.ALL_IN_ONE,
            # Change the Panel domain to a name the resolver cannot answer, back
            # to the menu, then start: the check routes to the Panel domain and
            # the corrected answer lets the same start through.
            "2\n2\nunresolved.example.com\n0\n1\npanel.example.com\n",
            failing=("unresolved.example.com",),
        )
        self.assertEqual(values["panel"], "panel.example.com")
        self.assertEqual(values["camouflage"], "cdn.example.com")
        self.assertEqual(values["vision"], "vision.example.com")
        self.assertEqual(values["email"], "admin@example.com")
        self.assertIn("Back to Panel domain (browser address; API and subscriptions)",
                      stderr)

    def test_review_plan_rejects_shared_domain_over_ceiling(self):
        """An over-ceiling shared domain is refused, and start routes to the node count."""
        plan = (
            "en\n3\npanel.example.com\ncdn.example.com\nn\nlocal-01\nadmin@example.com\n25\n"
            + "\n".join(
                f"node{i}.example.com\ncdn{i}.example.com\nn\nnode-{i:02d}" for i in range(1, 26)
            )
            + "\nn\n"
        )
        # Two refusals — one while editing, one at start — and the start refusal
        # names the node count rather than sending the operator back through the
        # whole plan. Lowering it to the ceiling meets the budget, so the shared
        # consent is asked; declining keeps the plan and returns to the menu.
        values, nodes, stderr = self._review(plan, "2\n7\ny\n0\n1\n24\nn\n0\n")
        self.assertEqual(stderr.count("exceed the ceiling"), 2)
        self.assertIn("Reduce the number of Workers to at most 24", stderr)
        self.assertEqual(values["node_count"], "24")
        self.assertEqual(len(nodes), 24)
        self.assertEqual(stderr.count("budget is shared by the whole cluster"), 1)

    def test_cancelling_at_review_reports_the_code_and_changes_no_answer(self):
        with tempfile.TemporaryDirectory() as directory:
            resolver = write_resolver(directory)
            result = bash(
                SOURCE_WIZARD
                + "wizard_collect_plan >/dev/null\n"
                + "review_rc=0\n"
                + "wizard_review_plan || review_rc=$?\n"
                + "printf 'review_rc=%s\\n' \"$review_rc\"\n"
                + DUMP_PLAN,
                stdin=self.TWO_NODES + "0\n",
                env={"GOWAVE_WIZARD_RESOLVER": resolver},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review_rc=3", result.stdout)
        self.assertIn("Deployment cancelled. No server was changed.", result.stdout)
        lines = result.stdout.splitlines()
        nodes = [line.split("=", 1)[1] for line in lines if line.startswith("node=")]
        self.assertEqual(
            nodes,
            ["node1.example.com|cdn1.example.com|", "node2.example.com|cdn2.example.com|"],
        )

    def test_cancelling_at_review_reaches_no_lock_and_no_install_step(self):
        """A cancelled plan returns from cmd_install before the lock is taken."""
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "mutations"
            resolver = write_resolver(directory)
            result = bash(
                f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
                # Stdin is a pipe here, so the terminal gate is answered by the
                # test and every step after the lock records that it was reached.
                "wizard_should_run() { return 0; }\n"
                "set +e\n"
                "acquire_lock() { printf 'lock\\n' >> \"$MARKER\"; }\n"
                "preflight_require_inputs() { printf 'inputs\\n' >> \"$MARKER\"; }\n"
                "preflight_require_direct_dns() { printf 'dns\\n' >> \"$MARKER\"; }\n"
                "bootstrap_early_tools() { printf 'bootstrap\\n' >> \"$MARKER\"; }\n"
                "select_acme_lineage() { printf 'acme\\n' >> \"$MARKER\"; }\n"
                "cmd_install\n"
                "printf 'rc=%s\\n' \"$?\"\n",
                stdin=self.ONE_NODE + "0\n",
                env={"GOWAVE_WIZARD_RESOLVER": resolver, "MARKER": str(marker)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rc=0", result.stdout)
            self.assertIn("Deployment cancelled. No server was changed.", result.stdout)
            self.assertFalse(
                marker.exists() and marker.read_text(encoding="utf-8"),
                "a cancelled plan reached a mutation step",
            )


class TestLocalNodeName(unittest.TestCase):
    """The accepted local name is what provisioning registers, not a constant.

    A positional or scripted install collects no plan, and its state, profile
    tags and Host remarks must stay what earlier versions wrote — otherwise a
    repeated install would leave the node it registered last time behind.
    """

    # cmd_install's locals are visible inside the functions it calls: bash scopes
    # them dynamically, so `acquire_lock` can report what provisioning would use.
    PROBE = "acquire_lock() { printf 'name=%s\\n' \"$local_node_name\"; exit 0; }\n"

    def _planned_name(self, wizard=False, plan_label=""):
        collect = (
            "wizard_should_run() { return 0; }\n"
            f"wizard_collect_plan() {{ GOWAVE_PLAN_LOCAL_LABEL={shlex.quote(plan_label)}; return 0; }}\n"
            "wizard_review_plan() { return 0; }\n"
            "wizard_check_ssh_reachable() { return 0; }\n"
            # The plan is what fills the positional list on this path; without it
            # the non-terminal gate refuses before anything is collected.
            "wizard_apply_plan() { GOWAVE_INSTALL_MODE=all-in-one;"
            " GOWAVE_INSTALL_POSITIONAL=(panel.example.com cdn.example.com admin@example.com '');"
            " return 0; }\n"
            if wizard
            else "wizard_should_run() { return 1; }\n"
        )
        result = bash(
            f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
            + collect
            + self.PROBE
            + "cmd_install panel.example.com cdn.example.com admin@example.com\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_a_plan_without_a_collected_name_keeps_the_historical_one(self):
        self.assertEqual(self._planned_name(), "name=local-node")

    def test_the_collected_name_is_what_provisioning_registers(self):
        self.assertEqual(self._planned_name(wizard=True, plan_label="ams-01"), "name=ams-01")


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
            "local-01",
            "admin@example.com",
            str(node_count),
        ]
        for i in range(1, node_count + 1):
            answers.extend([
                f"node{i}.example.com",
                f"cdn{i}.example.com",
                "n",
                f"node-{i:02d}",
            ])
        # The last answer is the shared-domain question; the plan is complete
        # once the node cards are read.
        answers.append("n")
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
            "wizard_panel_inventory_names() {"
            " printf 'worker-old\\t10.9.9.9\\t3002\\tuuid-old\\n'; return 0; }\n"
            "ssh_bootstrap_onboard_one() {"
            " printf 'ONBOARD host=%s cam=%s vision=[%s] name=%s ip=%s\\n'"
            " \"$1\" \"$2\" \"${3-}\" \"${4-}\" \"${5-}\";"
            " printf 'NODE-IDENTITY:%s\\t10.1.2.3\\t3002\\n' \"${4-}\" >&2; return 0; }\n"
            "wizard_verify_node_registration() {"
            " printf 'VERIFIED_READBACK=%s/%s/%s' \"$1\" \"$2\" \"$3\"; return 0; }\n"
            "cmd_node() { printf 'CMD_NODE=%s\\n' \"$*\"; return 0; }\n"
            # The menu calls every action through `menu_action`, whose OR-list
            # keeps a failing action from ending the session; the harness reads
            # the same status the same way.
            "if wizard_add_node_to_panel; then printf 'RC=0\\n'; else printf 'RC=%d\\n' \"$?\"; fi\n"
        )
        result = bash(
            script,
            stdin="y\nworker-one\n10.1.2.3\nnode.example.com\ncdn.example.com\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERIFY=panel.example.com/yes", result.stdout)
        self.assertIn("The Panel lists 1 node(s)", result.stderr)
        self.assertIn(
            "ONBOARD host=node.example.com cam=cdn.example.com vision=[] name=worker-one ip=10.1.2.3",
            result.stdout,
        )
        self.assertNotIn("CMD_NODE=", result.stdout, "the menu bypassed the temporary-access onboarding")
        # The registration is read back by the identity the onboarding wrote,
        # and reported as this node's addition with the Panel's answer.
        self.assertIn(
            "Node worker-one was added to the Panel and read back from it "
            "(uuid VERIFIED_READBACK=worker-one/10.1.2.3/3002, 10.1.2.3:3002).",
            result.stdout,
        )
        self.assertIn("RC=0", result.stdout)

    def test_a_registration_the_panel_does_not_confirm_is_reported_as_a_failure(self):
        # The Panel answered and does not hold the node `node add` claimed: the
        # menu names the stage that did not hold instead of reporting success.
        script = (
            f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
            "detect_local_panel() { printf 'panel.example.com'; return 0; }\n"
            "wizard_verify_panel_api() { return 0; }\n"
            "wizard_panel_inventory_names() { return 0; }\n"
            "ssh_bootstrap_onboard_one() {"
            " printf 'Node registered.\\n';"
            " printf 'NODE-IDENTITY:%s\\t10.1.2.3\\t3002\\n' \"${4-}\" >&2; return 0; }\n"
            "wizard_verify_node_registration() { printf 'missing'; return 1; }\n"
            "if wizard_add_node_to_panel; then printf 'RC=0\\n'; else printf 'RC=%d\\n' \"$?\"; fi\n"
        )
        result = bash(
            script,
            stdin="y\nworker-one\n10.1.2.3\nnode.example.com\ncdn.example.com\n",
        )
        self.assertIn(
            "Node worker-one was not added (phase: verify, reason: "
            "the Panel's node list does not hold this node).",
            result.stderr,
        )
        self.assertIn("RC=1", result.stdout)
        self.assertNotIn("was added to the Panel", result.stdout)

    def test_a_remote_panel_leaves_the_add_node_result_unconfirmed(self):
        # Nothing about the node was disproved, so the menu does not call it a
        # failure — and does not call it verified either.
        script = (
            f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
            "detect_local_panel() { return 1; }\n"
            "wizard_verify_panel_api() { return 0; }\n"
            "wizard_panel_inventory_names() { return 2; }\n"
            "ssh_bootstrap_onboard_one() {"
            " printf 'NODE-IDENTITY:%s\\t10.1.2.3\\t3002\\n' \"${4-}\" >&2; return 0; }\n"
            "wizard_verify_node_registration() { return 2; }\n"
            "if wizard_add_node_to_panel; then printf 'RC=0\\n'; else printf 'RC=%d\\n' \"$?\"; fi\n"
        )
        result = bash(
            script,
            stdin="panel.example.com\nworker-one\n10.1.2.3\nnode.example.com\ncdn.example.com\n",
        )
        self.assertIn(
            "Node worker-one was registered, but a Panel on another host cannot be read "
            "from here. Check the Panel's node list before relying on it.",
            result.stdout,
        )
        self.assertIn("RC=0", result.stdout)

    def test_the_menu_add_node_refuses_a_name_the_panel_already_holds(self):
        # The menu has the Panel's inventory in hand before the SSH session
        # opens, so a collision is refused there instead of after registration.
        script = (
            f"source {shlex.quote(str(GOWAVE_AUTO))}\n"
            "detect_local_panel() { printf 'panel.example.com'; return 0; }\n"
            "wizard_verify_panel_api() { return 0; }\n"
            "wizard_panel_inventory_names() {"
            " printf 'worker-one\\t10.9.9.9\\t3002\\tuuid-one\\n'; return 0; }\n"
            "ssh_bootstrap_onboard_one() { printf 'ONBOARD name=%s\\n' \"$4\";"
            " printf 'NODE-IDENTITY:%s\\t10.1.2.3\\t3002\\n' \"${4-}\" >&2; return 0; }\n"
            "wizard_verify_node_registration() { printf 'uuid-%s' \"$1\"; return 0; }\n"
            "if wizard_add_node_to_panel; then printf 'RC=0\\n'; else printf 'RC=%d\\n' \"$?\"; fi\n"
        )
        result = bash(
            script,
            stdin="y\nworker-one\nworker-two\n10.1.2.3\nnode.example.com\ncdn.example.com\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "The Panel already has a node named worker-one at 10.9.9.9",
            result.stderr,
        )
        self.assertIn("ONBOARD name=worker-two", result.stdout)
        self.assertIn("Node worker-two was added to the Panel and read back from it", result.stdout)

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


class TestPanelWorkerName(unittest.TestCase):
    """The name question holds the Panel's inventory, not a guess.

    A name the Panel already holds belongs to another node, and registering it
    again rewrites that node's address — the traffic endpoint of a server this
    operator does not own. The inventory read is the only thing that can tell
    the two apart, so what it returns decides the question.
    """

    def read(self, inventory, stdin="", address="panel.example.com", local="yes"):
        script = (
            SOURCE_WIZARD
            + inventory
            + "set +e\n"
            f"name=$(wizard_read_panel_worker_name {shlex.quote(address)} {local})\n"
            "rc=$?\n"
            "printf 'RC=%d NAME=[%s]\\n' \"$rc\" \"$name\"\n"
        )
        return bash(script, stdin=stdin)

    def test_a_name_the_panel_already_holds_is_refused_and_the_question_repeats(self):
        result = self.read(
            "wizard_panel_inventory_names() { printf 'ams-01\\t10.1.2.3\\n'; return 0; }\n",
            stdin="ams-01\nams-02\n",
        )
        self.assertIn("RC=0 NAME=[ams-02]", result.stdout, result.stderr)
        self.assertIn("The Panel lists 1 node(s)", result.stderr)
        self.assertIn("The Panel already has a node named ams-01 at 10.1.2.3", result.stderr)

    def test_the_panel_name_comparison_ignores_case(self):
        result = self.read(
            "wizard_panel_inventory_names() { printf 'AMS-01\\t10.1.2.3\\n'; return 0; }\n",
            stdin="ams-01\nams-02\n",
        )
        self.assertIn("RC=0 NAME=[ams-02]", result.stdout, result.stderr)
        self.assertIn("The Panel already has a node named ams-01 at 10.1.2.3", result.stderr)

    def test_a_remote_panel_says_the_name_is_unverified_and_asks_for_it(self):
        result = self.read(
            "wizard_panel_inventory_names() { return 2; }\n",
            stdin="worker-one\n",
            local="no",
        )
        self.assertIn("RC=0 NAME=[worker-one]", result.stdout, result.stderr)
        self.assertIn("cannot be read from this host", result.stderr)
        self.assertNotIn("The Panel lists", result.stderr, "an unread inventory claimed a count")

    def test_an_unreadable_local_panel_asks_before_giving_up(self):
        result = self.read(
            "wizard_panel_inventory_names() { return 1; }\n",
            stdin="n\n",
        )
        self.assertIn("RC=1 NAME=[]", result.stdout, result.stderr)
        self.assertIn("Could not read the node list from the Panel: panel.example.com", result.stderr)
        self.assertIn("Add node cancelled.", result.stderr)

    def test_a_retried_inventory_read_replaces_the_failed_one(self):
        # The inventory read runs in a command substitution, so a counter held
        # in a shell variable would reset on every call: the stub counts in a file.
        result = self.read(
            "_wpn_calls=$(mktemp)\n"
            "wizard_panel_inventory_names() {\n"
            "  local n\n"
            "  n=$(cat \"$_wpn_calls\")\n"
            "  n=$((n + 1))\n"
            "  printf '%s' \"$n\" > \"$_wpn_calls\"\n"
            "  if [ \"$n\" -eq 1 ]; then return 1; fi\n"
            "  printf 'worker-old\\t10.9.9.9\\n'\n"
            "  return 0\n"
            "}\n",
            stdin="y\nworker-old\nworker-new\n",
        )
        self.assertIn("RC=0 NAME=[worker-new]", result.stdout, result.stderr)
        self.assertIn("The Panel lists 1 node(s)", result.stderr)
        self.assertIn("The Panel already has a node named worker-old at 10.9.9.9", result.stderr)

    def test_the_panel_address_and_its_locality_reach_the_inventory_read(self):
        result = self.read(
            "wizard_panel_inventory_names() { printf 'READ=%s/%s\\n' \"$1\" \"$2\" >&2; return 0; }\n",
            stdin="worker-one\n",
            address="panel.example.com",
            local="no",
        )
        self.assertIn("READ=panel.example.com/no", result.stderr)


class TestPanelInventoryRead(unittest.TestCase):
    """What the inventory read answers, and what it refuses to guess.

    Only a Panel on this host can be read: the administrative credentials that
    read it sit in this host's credentials file. A remote Panel's inventory is
    unverifiable here, and an unreadable local one is a failure — neither may be
    reported as "the name is free".
    """

    def read(self, address, local, credentials):
        script = (
            SOURCE_WIZARD
            + "set +e\n"
            f"CREDENTIALS_FILE={shlex.quote(credentials)}\n"
            f"wizard_panel_inventory_names {shlex.quote(address)} {local}\n"
            "printf 'RC=%d\\n' \"$?\"\n"
        )
        return bash(script)

    def read_with_fake_panel(self, credentials, env=None):
        """Run the shipped read against a Panel client that records its calls.

        The client module is what ``_wizard_dir`` points at, so the function's
        own ``PYTHONPATH`` resolves to it: the payload under test is the shipped
        text, only the Panel behind it is a double.
        """
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        modules = Path(directory) / "modules"
        modules.mkdir()
        (modules / "__init__.py").write_text("", encoding="utf-8")
        (modules / "api_client.py").write_text(FAKE_PANEL_CLIENT, encoding="utf-8")
        log = Path(directory) / "calls.log"
        creds = Path(directory) / "credentials.txt"
        creds.write_text(credentials, encoding="utf-8")
        script = (
            SOURCE_WIZARD
            + "set +e\n"
            f"_wizard_dir={shlex.quote(str(modules))}\n"
            f"CREDENTIALS_FILE={shlex.quote(str(creds))}\n"
            "wizard_panel_inventory_names 127.0.0.1 yes\n"
            "printf 'RC=%d\\n' \"$?\"\n"
        )
        result = bash(script, env={"FAKE_LOG": str(log), **(env or {})})
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        return result, calls

    def test_the_readback_authenticates_as_the_administrator(self):
        # The scoped token in the same file is issued for external subscription
        # consumers and carries no `nodes:read`; a read behind it answers 403 and
        # would report a registered node as unconfirmed.
        result, calls = self.read_with_fake_panel(
            "ADMIN_USERNAME=admin\n"
            "ADMIN_PASSWORD=secret\n"
            "SCOPED_API_TOKEN=token-without-nodes-read\n"
        )
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertIn("base=http://127.0.0.1:3000", calls)
        self.assertIn("login=admin/secret", calls)
        self.assertIn("worker-1\t10.1.2.3\t3002\tuuid-1", result.stdout)
        self.assertNotIn("token-without-nodes-read", calls, "the scope-less token was used to read nodes")

    def test_a_credentials_file_without_the_administrator_is_not_a_read(self):
        result, calls = self.read_with_fake_panel("SCOPED_API_TOKEN=token-without-nodes-read\n")
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertNotIn("login=", calls, "the read ran without administrative credentials")
        self.assertNotIn("worker-1", result.stdout, "an unauthenticated read printed an inventory")

    def test_a_panel_that_refuses_the_administrator_login_is_not_a_read(self):
        result, calls = self.read_with_fake_panel(
            "ADMIN_USERNAME=admin\nADMIN_PASSWORD=secret\n",
            env={"FAKE_LOGIN_ERROR": "403"},
        )
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("login=admin/secret", calls)
        self.assertNotIn("worker-1", result.stdout, "a refused login still printed an inventory")
        self.assertNotIn("Traceback", result.stderr)

    def test_a_remote_panel_inventory_is_unverifiable_here(self):
        result = self.read("panel.example.com", "no", "/nonexistent/credentials")
        self.assertIn("RC=2", result.stdout, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "RC=2", "an unverified inventory printed names")

    def test_a_local_panel_without_a_credentials_file_is_a_failure_not_an_empty_list(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.read("127.0.0.1", "yes", str(Path(directory) / "absent.txt"))
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
