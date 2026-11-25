#!/usr/bin/env python3
"""Suite nonroot: the exit country a traffic node is labelled with.

The country belongs to the node's own outbound route, so these tests drive the
shipped functions from both ends: once with the answer produced on this host,
once with the answer arriving from a Worker over the SSH session the onboarding
already opened. A lookup service is never contacted — every test puts a stub
`curl`/`wget` first on PATH — and the two cases that must not ask at all are
observed through a marker the stub would create.

Two guards read the shipped script instead of running it, because the branch they
protect has nothing to run here: a Panel-only install executes no local-node
step, so "the Panel-only host asks nothing" is a property of where the call sits.
"""
import importlib
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GEOIP_SH = REPO_ROOT / "modules" / "geoip.sh"
WIZARD_SH = REPO_ROOT / "modules" / "wizard.sh"
GOWAVE_AUTO = REPO_ROOT / "gowave-auto.sh"

SOURCE_GEOIP = f"source {shlex.quote(str(GEOIP_SH))}\n"


def bash(script, stdin="", env=None):
    merged = dict(os.environ)
    merged.pop("GOWAVE_WIZARD_LANG", None)
    merged.pop("GOWAVE_COUNTRY_ASK", None)
    merged.update(env or {})
    return subprocess.run(
        ["bash", "-c", script],
        input=stdin,
        text=True,
        capture_output=True,
        env=merged,
        timeout=120,
        # A scripted run has no controlling terminal, so a question goes to the
        # captured stream instead of a tty inherited from the test harness.
        start_new_session=True,
    )


def write_executable(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def write_curl_stub(directory, answer="", log=None, marker=None):
    """A `curl` that answers instead of contacting anything.

    ``answer`` is the body it prints, ``log`` receives one line per call so a
    test can read the bound and the URL the product asked with, and ``marker``
    is created on the first call, which is how "no request was made" is proven.
    """
    lines = ["#!/bin/sh"]
    if marker:
        lines.append(f': >> {shlex.quote(str(marker))}')
    if log:
        lines.append(f'printf "%s\\n" "$*" >> {shlex.quote(str(log))}')
    if answer:
        lines.append(f"printf '%s\\n' {shlex.quote(answer)}")
    lines.append("exit 0")
    return write_executable(Path(directory) / "curl", "\n".join(lines) + "\n")


class TestCountryCodes(unittest.TestCase):
    def test_only_an_assigned_code_is_a_country(self):
        # `UK` and `EU` are what a service or a hurried operator may type; they
        # are not assigned countries, and a fragment is not a country either.
        result = bash(
            SOURCE_GEOIP
            + "printf 'de=[%s]\\n' \"$(country_normalize ' de ')\"\n"
            "printf 'upper=[%s]\\n' \"$(country_normalize 'DE')\"\n"
            "printf 'mixed=[%s]\\n' \"$(country_normalize 'De')\"\n"
            "printf 'split=[%s]\\n' \"$(country_normalize 'N L')\"\n"
            "printf 'uk=[%s]\\n' \"$(country_normalize 'UK')\"\n"
            "printf 'eu=[%s]\\n' \"$(country_normalize 'EU')\"\n"
            "printf 'short=[%s]\\n' \"$(country_normalize 'D')\"\n"
            "printf 'long=[%s]\\n' \"$(country_normalize 'DEU')\"\n"
            "printf 'empty=[%s]\\n' \"$(country_normalize '')\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("de=[DE]", result.stdout)
        self.assertIn("upper=[DE]", result.stdout)
        self.assertIn("mixed=[DE]", result.stdout)
        self.assertIn("split=[NL]", result.stdout)
        self.assertIn("uk=[]", result.stdout)
        self.assertIn("eu=[]", result.stdout)
        self.assertIn("short=[]", result.stdout)
        self.assertIn("long=[]", result.stdout)
        self.assertIn("empty=[]", result.stdout)

    def test_a_lookup_answer_is_read_as_one_bare_line(self):
        result = bash(
            SOURCE_GEOIP
            + "printf 'plain=[%s]\\n' \"$(printf 'de\\n' | country_parse)\"\n"
            "printf 'trailing=[%s]\\n' \"$(printf 'nl\\nHTTP/1.1 200 OK\\n' | country_parse)\"\n"
            "printf 'json=[%s]\\n' \"$(printf '{\"country\":\"NL\"}' | country_parse)\"\n"
            "printf 'prose=[%s]\\n' \"$(printf 'You are in Germany.\\n' | country_parse)\"\n"
            "printf 'silent=[%s]\\n' \"$(printf '' | country_parse)\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("plain=[DE]", result.stdout)
        # Only the first line is the answer: a status line beneath it is not.
        self.assertIn("trailing=[NL]", result.stdout)
        self.assertIn("json=[]", result.stdout)
        self.assertIn("prose=[]", result.stdout)
        self.assertIn("silent=[]", result.stdout)

    def test_a_flag_is_two_regional_indicators_and_nothing_else(self):
        result = bash(
            SOURCE_GEOIP
            + "printf 'de=%s\\n' \"$(country_flag DE | od -An -tx1 | tr -d ' \\n')\"\n"
            "printf 'length=%s\\n' \"$(printf '%s' \"$(country_flag DE)\" | wc -m | tr -d ' ')\"\n"
            "printf 'unknown=[%s]\\n' \"$(country_flag ZZ)\"\n"
            "printf 'lower=[%s]\\n' \"$(country_flag de)\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # U+1F1E9 U+1F1EA: the letters D and E as regional indicators.
        self.assertIn("de=f09f87a9f09f87aa", result.stdout)
        self.assertIn("length=2", result.stdout)
        self.assertIn("unknown=[]", result.stdout)
        self.assertIn("lower=[]", result.stdout)

    def test_a_name_comes_from_the_catalog_and_falls_back_to_the_code(self):
        result = bash(
            SOURCE_GEOIP
            + "GOWAVE_WIZARD_LANG=en; printf 'en=[%s]\\n' \"$(country_name DE)\"\n"
            "GOWAVE_WIZARD_LANG=ru; printf 'ru=[%s]\\n' \"$(country_name de)\"\n"
            "printf 'unnamed=[%s]\\n' \"$(country_name AQ)\"\n"
            "printf 'empty=[%s]\\n' \"$(country_name '')\"\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("en=[Germany]", result.stdout)
        self.assertIn("ru=[Германия]", result.stdout)
        # Antarctica is assigned but has no name in the catalog: the code beside
        # the flag is still unambiguous, so it is shown instead of a missing word.
        self.assertIn("unnamed=[AQ]", result.stdout)
        self.assertIn("empty=[]", result.stdout)


class TestCountryLookup(unittest.TestCase):
    def test_the_request_is_bounded_and_made_by_this_host(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "curl.log"
            write_curl_stub(directory, answer="nl", log=log)
            result = bash(
                SOURCE_GEOIP
                + "printf 'answer=[%s]\\n' \"$(country_lookup_here)\"\n",
                env={
                    "PATH": f"{directory}:/usr/bin:/bin",
                    "GOWAVE_COUNTRY_LOOKUP_URL": "https://lookup.test/country",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("answer=[NL]", result.stdout)
            called = log.read_text(encoding="utf-8")
            self.assertIn("--max-time 5", called)
            self.assertIn("https://lookup.test/country", called)
            self.assertIn("-fsS", called)

    def test_the_timeout_is_the_one_the_operator_set(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "curl.log"
            write_curl_stub(directory, answer="fr", log=log)
            result = bash(
                SOURCE_GEOIP + "country_lookup_here\n",
                env={
                    "PATH": f"{directory}:/usr/bin:/bin",
                    "GOWAVE_COUNTRY_LOOKUP_TIMEOUT": "2",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--max-time 2", log.read_text(encoding="utf-8"))

    def test_a_failed_request_answers_nothing_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            # curl's own timeout exit status, with no body at all.
            write_executable(Path(directory) / "curl", "#!/bin/sh\nexit 28\n")
            result = bash(
                SOURCE_GEOIP
                + "code=$(country_lookup_here); printf 'rc=%s answer=[%s]\\n' \"$?\" \"$code\"\n",
                env={"PATH": f"{directory}:/usr/bin:/bin"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rc=0 answer=[]", result.stdout)

    def test_the_worker_runs_the_request_the_product_renders(self):
        # The rendered payload is what a Worker executes under `bash -s`; running
        # it here with a stub proves the command carries the same bound and URL
        # rather than merely mentioning them.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "curl.log"
            write_curl_stub(directory, answer="de", log=log)
            result = bash(
                SOURCE_GEOIP
                + "rendered=$(country_lookup_command)\n"
                "printf 'rendered<<%s>>\\n' \"$rendered\"\n"
                "printf 'ran=[%s]\\n' \"$(eval \"$rendered\" | country_parse)\"\n",
                env={
                    "PATH": f"{directory}:/usr/bin:/bin",
                    "GOWAVE_COUNTRY_LOOKUP_URL": "https://lookup.test/worker-country",
                    "GOWAVE_COUNTRY_LOOKUP_TIMEOUT": "3",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ran=[DE]", result.stdout)
            called = log.read_text(encoding="utf-8")
            self.assertIn("--max-time 3", called)
            self.assertIn("https://lookup.test/worker-country", called)


class TestCountryConfirmation(unittest.TestCase):
    def confirm(self, answers, suggestion, label="ams-01", env=None):
        # The question goes to the prompt stream, which is a terminal in a real
        # run; a file would only keep the last write, so the captured stream is
        # read instead of the default /dev/stderr being redirected.
        result = bash(
            SOURCE_GEOIP
            + f"if country_confirm {shlex.quote(label)} {shlex.quote(suggestion)}; then"
            f" printf 'RC=0\\n'; else printf 'RC=%d\\n' \"$?\"; fi\n",
            stdin=answers,
            env=env,
        )
        return result, result.stderr

    def test_enter_accepts_the_suggestion(self):
        result, printed = self.confirm("\n", "NL")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=0", result.stdout)
        # The accepted code is the function's stdout, and only that.
        self.assertEqual(result.stdout.replace("RC=0\n", ""), "NL")
        self.assertIn("Exit country of ams-01: 🇳🇱 Netherlands (NL)", printed)
        self.assertIn("Press Enter to confirm", printed)

    def test_a_typed_code_overrides_the_suggestion_in_any_case(self):
        result, printed = self.confirm("de\n", "NL")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.replace("RC=0\n", ""), "DE")
        # Correction is shown back before it is used: name, code and flag.
        self.assertIn("Germany", printed)
        self.assertIn("(DE)", printed)
        self.assertIn("🇩🇪", printed)

    def test_invalid_input_repeats_only_this_question(self):
        result, printed = self.confirm("UK\nZZ\nde\n", "NL")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.replace("RC=0\n", ""), "DE")
        self.assertEqual(printed.count("That is not an assigned two-letter country code"), 2)
        self.assertEqual(printed.count("Exit country check:"), 1,
                         "the disclosure is printed once, not on every attempt")
        # One question per attempt, plus the correction shown back as the code
        # the operator typed, which is not the suggestion that was refused.
        self.assertEqual(printed.count("Exit country of ams-01:"), 4)
        self.assertIn("Exit country of ams-01: 🇩🇪 Germany (DE)", printed)

    def test_without_a_suggestion_the_code_is_required_and_never_guessed(self):
        result, printed = self.confirm("\n\nfr\n", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.replace("RC=0\n", ""), "FR")
        self.assertEqual(
            printed.count("The country lookup did not answer for ams-01."), 3,
            "an empty answer without a suggestion is asked again"
        )
        # Nothing names a country until the operator has supplied one, and then
        # it is the one typed, read back with its flag and name.
        self.assertEqual(printed.count("Exit country of ams-01:"), 1)
        self.assertIn("Exit country of ams-01: 🇫🇷 France (FR)", printed)
        self.assertEqual(printed.count("That is not an assigned two-letter country code"), 2)

    def test_an_ended_input_returns_nothing_rather_than_a_country(self):
        result, _ = self.confirm("", "NL")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RC=1", result.stdout)
        self.assertNotIn("NL", result.stdout)

    def test_the_disclosure_names_the_service_and_the_source_address(self):
        _, printed = self.confirm("\n", "NL", env={"GOWAVE_COUNTRY_LOOKUP_URL": "https://lookup.test/c"})
        self.assertIn("one request from the node itself to https://lookup.test/c", printed)
        self.assertIn("sees the node's address and nothing else", printed)


class TestCountryGate(unittest.TestCase):
    def test_no_wizard_means_no_question_and_no_request(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "called"
            write_curl_stub(directory, answer="nl", marker=marker)
            result = bash(
                f"source {shlex.quote(str(WIZARD_SH))}\n"
                "code=$(wizard_local_exit_country ams-01) || code=\"\"\n"
                "printf 'RC=0 code=[%s]\\n' \"$code\"\n",
                env={"PATH": f"{directory}:/usr/bin:/bin"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("code=[]", result.stdout)
            self.assertFalse(marker.exists(), "a run without a wizard contacted a lookup service")

    def test_the_wizard_asks_this_hosts_own_route(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "called"
            write_curl_stub(directory, answer="us", marker=marker)
            result = bash(
                f"source {shlex.quote(str(WIZARD_SH))}\n"
                "GOWAVE_COUNTRY_ASK=yes\n"
                "code=$(wizard_local_exit_country ams-01) || code=\"\"\n"
                "printf 'RC=0 code=[%s]\\n' \"$code\"\n",
                stdin="\n",
                env={"PATH": f"{directory}:/usr/bin:/bin"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("code=[US]", result.stdout)
            self.assertTrue(marker.exists())
            self.assertIn("Exit country of ams-01: 🇺🇸 United States (US)", result.stderr)


ONBOARD_STUBS = (
    "ssh_bootstrap_prepare_key() { GOWAVE_SSH_TEMP_ROOT=$STUB_ROOT;"
    " GOWAVE_SSH_KEY=$STUB_ROOT/id; : > \"$GOWAVE_SSH_KEY.pub\";"
    " GOWAVE_SSH_KNOWN_HOSTS=$STUB_ROOT/known_hosts; : > \"$GOWAVE_SSH_KNOWN_HOSTS\"; }\n"
    "ssh_bootstrap_scan() { echo 'worker.example.com ssh-ed25519 AAAA'; }\n"
    "ssh_bootstrap_fingerprint() { echo 'SHA256:test'; }\n"
    "ssh_bootstrap_confirm_fingerprint() { return 0; }\n"
    "ssh_bootstrap_prepare_password() { echo \"$STUB_PASSWORD\"; }\n"
    "ssh_bootstrap_authorise() { return 0; }\n"
    "ssh_bootstrap_revoke() { return 0; }\n"
    "ssh_bootstrap_start_agent() { GOWAVE_SSH_AGENT_SOCK=stub; return 0; }\n"
    "ssh_bootstrap_stop_agent() { :; }\n"
    # The Worker answers the payload it is sent; the payload is captured so the
    # request the product would run there can be read afterwards.
    "ssh() { printf 'SSH %s\\n' \"$*\" >> \"$STUB_LOG\";"
    " cat > \"$STUB_PAYLOAD\"; printf '%s\\n' \"${WORKER_ANSWER:-}\"; }\n"
    "wizard_resolve_ipv4() { echo 203.0.113.7; }\n"
    "cmd_node() { printf 'NODE country=[%s] args=%s\\n' \"${GOWAVE_NODE_COUNTRY:-}\" \"$*\""
    " >> \"$STUB_LOG\"; return 0; }\n"
)


class TestOnboardingCountry(unittest.TestCase):
    def onboard(self, answers="", worker_answer="", ask="yes"):
        directory = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        password = Path(directory) / "password"
        password.write_text("s3cret\n", encoding="utf-8")
        password.chmod(0o600)
        log = Path(directory) / "stub.log"
        payload = Path(directory) / "payload"
        env = {
            "STUB_ROOT": directory,
            "STUB_LOG": str(log),
            "STUB_PASSWORD": str(password),
            "STUB_PAYLOAD": str(payload),
            "WORKER_ANSWER": worker_answer,
        }
        if ask == "yes":
            env["GOWAVE_COUNTRY_ASK"] = "yes"
        result = bash(
            SOURCE_GEOIP
            + "source " + shlex.quote(str(WIZARD_SH)) + "\n"
            + ONBOARD_STUBS
            + "if ssh_bootstrap_onboard_one worker.example.com cdn.example.com;"
            " then echo RC=0; else echo RC=1; fi\n",
            stdin=answers,
            env=env,
        )
        return (
            result,
            log.read_text(encoding="utf-8") if log.exists() else "",
            payload.read_text(encoding="utf-8") if payload.exists() else "",
        )

    def test_the_worker_is_asked_over_the_session_that_was_already_opened(self):
        result, log, payload = self.onboard(answers="\n", worker_answer="de")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PHASE:country", result.stderr)
        # The request is the Worker's: addressed to it, on the onboarding port,
        # and carrying the bounded lookup rather than the Panel's address.
        self.assertIn("root@worker.example.com", log)
        self.assertIn("-p 22", log)
        # The payload states the bound once and uses it in the request; the
        # rendered command is run by its own test, so this reads what travels.
        self.assertIn("limit=5", payload)
        self.assertIn('--max-time "$limit"', payload)
        self.assertIn("ipinfo.io/country", payload)
        # The payload travels to a host this installer has just taken temporary
        # access to, so it opens with the same strict mode as every other one.
        self.assertTrue(payload.startswith("set -Eeuo pipefail\n"))
        self.assertIn("NODE country=[DE]", log)
        self.assertIn("Exit country of worker.example.com: 🇩🇪 Germany (DE)", result.stderr)
        self.assertLess(result.stderr.index("PHASE:start_agent"), result.stderr.index("PHASE:country"))
        self.assertLess(result.stderr.index("PHASE:country"), result.stderr.index("PHASE:add_node"))

    def test_a_lookup_that_does_not_answer_falls_back_to_the_operator(self):
        result, log, _ = self.onboard(answers="nl\n", worker_answer="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NODE country=[NL]", log)
        self.assertIn("The country lookup did not answer for worker.example.com.", result.stderr)

    def test_a_legacy_run_asks_nothing_and_registers_no_country(self):
        result, log, payload = self.onboard(answers="", worker_answer="de", ask="no")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PHASE:country", result.stderr)
        self.assertNotIn("SSH ", log, "a run without a wizard opened a lookup session")
        self.assertEqual(payload, "")
        self.assertIn("NODE country=[]", log)
        self.assertNotIn("Exit country", result.stderr)

    def test_the_two_nodes_of_one_plan_can_be_suggested_different_countries(self):
        # The local node's answer comes from this host, the Worker's from itself:
        # the same run must not reduce both to one origin.
        with tempfile.TemporaryDirectory() as directory:
            write_curl_stub(directory, answer="us")
            log = Path(directory) / "stub.log"
            payload = Path(directory) / "payload"
            password = Path(directory) / "password"
            password.write_text("s3cret\n", encoding="utf-8")
            password.chmod(0o600)
            result = bash(
                f"source {shlex.quote(str(WIZARD_SH))}\n"
                + ONBOARD_STUBS
                + "GOWAVE_COUNTRY_ASK=yes\n"
                "local_code=$(wizard_local_exit_country local-node) || local_code=\"\"\n"
                "printf 'LOCAL=[%s]\\n' \"$local_code\"\n"
                "ssh_bootstrap_onboard_one worker.example.com cdn.example.com \"\" "
                "worker-1 203.0.113.9 || true\n",
                stdin="\n\n",
                env={
                    "PATH": f"{directory}:/usr/bin:/bin",
                    "STUB_ROOT": directory,
                    "STUB_LOG": str(log),
                    "STUB_PASSWORD": str(password),
                    "STUB_PAYLOAD": str(payload),
                    "WORKER_ANSWER": "de",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("LOCAL=[US]", result.stdout)
            self.assertIn("NODE country=[DE]", log.read_text(encoding="utf-8"))
            self.assertIn("Exit country of local-node: 🇺🇸 United States (US)", result.stderr)
            self.assertIn("Exit country of worker-1: 🇩🇪 Germany (DE)", result.stderr)


class TestNodeCountryPersistence(unittest.TestCase):
    def test_a_confirmed_code_is_stored_and_an_unasked_run_keeps_it(self):
        api_client = importlib.import_module("modules.api_client")
        # A typed answer wins, in any case.
        self.assertEqual(api_client.confirmed_country("de", ""), "DE")
        # A run that asked nothing keeps what the node entry already held...
        self.assertEqual(api_client.confirmed_country("", "nl"), "NL")
        # ...and nothing at all is stored for a node with no confirmed country,
        # which is what keeps a flag from being invented.
        self.assertEqual(api_client.confirmed_country("", ""), "")
        # The assigned set lives in the shell catalog, where the operator's answer
        # is checked. This reader is a second one for shape, not a second catalog:
        # a value that reaches it has already passed that check.
        self.assertEqual(api_client.confirmed_country("uk", "DE"), "UK")
        self.assertEqual(api_client.confirmed_country("Germany", "DE"), "DE")

    def test_both_node_paths_write_the_confirmed_country_into_the_identity(self):
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        self.assertIn('GOWAVE_LOCAL_COUNTRY="$local_country"', source)
        self.assertIn('local_node_entry["country"] = local_country', source)
        self.assertIn('node_entry["country"] = node_country', source)
        # The key is written only when a country is known: an empty answer must
        # not appear in state.json as an empty label.
        self.assertIn("if local_country:", source)
        self.assertIn("if node_country:", source)


class TestCountryScope(unittest.TestCase):
    def test_the_local_node_is_asked_only_where_it_serves(self):
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        install = source[source.index("cmd_install() {"):source.index("\ncmd_node() {")]
        self.assertEqual(install.count("wizard_local_exit_country"), 1,
                         "a Panel-only host runs no local node, so it must not ask")
        start = install.index('if [[ "$install_mode" == "all-in-one" ]]')
        branch = install[start:install.index("    else\n", start)]
        self.assertIn("wizard_local_exit_country", branch)
        self.assertLess(branch.index("verify_node_mtls_health"),
                        branch.index("wizard_local_exit_country"),
                        "the country is asked only once the node serves")
        self.assertIn("configure_ufw false \"\" 3002", branch)
        panel_only = install[start:install.index("    fi\n", start)]
        self.assertNotIn("wizard_local_exit_country", panel_only.split("    else\n", 1)[1])

    def test_only_the_two_interactive_entrypoints_ask(self):
        source = GOWAVE_AUTO.read_text(encoding="utf-8")
        self.assertEqual(source.count('GOWAVE_COUNTRY_ASK="yes"'), 2)
        install = source[source.index("cmd_install() {"):source.index("\ncmd_node() {")]
        wizard_branch = install[
            install.index('if wizard_should_run "$@"'):
            install.index("    else\n        if [[ $# -eq 0 ]]")
        ]
        self.assertIn('GOWAVE_COUNTRY_ASK="yes"', wizard_branch)
        add_node = source[source.index("wizard_add_node_to_panel() {"):]
        add_node = add_node[:add_node.index("\n# An interactive screen")]
        self.assertIn('GOWAVE_COUNTRY_ASK="yes"', add_node)
