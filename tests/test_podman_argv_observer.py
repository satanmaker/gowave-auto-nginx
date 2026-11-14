#!/usr/bin/env python3
"""Suite nonroot: the Master-side argv observer (WRK-01..03).

What a live Multi-Node run proves is that the dispatch really was traced on the
Master and really did not carry the secret. What this file holds is the part the
run depends on being right: the scanner reads strace the way strace writes it —
escapes, a cut string, an abbreviated array, a record split across two lines —
and the acceptance fixtures refuse an observer that cannot see a sentinel whole.
A parser that misses a marker would turn an incomplete observation into a PASS,
which is the one failure this observer exists to prevent.
"""
import base64
import contextlib
import sys
import types
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import argv_probe, multi_node, topology  # noqa: E402

SECRET = "8b1c0f7a9d4e6f2a5c8b1d4e7f0a3c6b"


SSH_CLIENT = "ssh"


def scan(text, secrets, client=SSH_CLIENT):
    """The scanner with the client name a Master would have reported."""
    return argv_probe.scan_trace_text(text, list(secrets), client)


def exec_line(argv, syscall="execve", env=("PATH=/usr/bin",), pid=""):
    """One strace exec record, rendered the way strace renders it."""
    def array(elements):
        return "[" + ", ".join(f'"{element}"' for element in elements) + "]"

    prefix = f"{pid} " if pid else ""
    if syscall == "execveat":
        call = f'execveat(AT_FDCWD, "/usr/bin/python3", {array(argv)}, {array(env)}, 0) = 0'
    else:
        call = f'execve("/usr/bin/python3", {array(argv)}, {array(env)}) = 0'
    return prefix + call


class TestStraceParsing(unittest.TestCase):
    """The scanner reads argv vectors only, and says when one is not whole."""

    def test_a_complete_record_reports_its_exec_and_no_omission(self):
        text = exec_line(["ssh", "-o", "BatchMode=yes", "root@10.89.0.12", "true"])
        facts = scan(text, [SECRET])
        self.assertEqual(facts["status"], "PASS")
        self.assertEqual(facts["exec_count"], 1)
        self.assertEqual(facts["ssh_execs"], 1)
        self.assertFalse(facts["truncated"])
        self.assertFalse(facts["abbreviated"])
        self.assertEqual(facts["errors"], [])

    def test_a_string_cut_at_the_limit_is_reported(self):
        text = (
            'execve("/usr/bin/python3", ["python3", "-c", "pass", '
            '"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"...], ["PATH=/usr/bin"]) = 0'
        )
        facts = scan(text, [SECRET])
        self.assertTrue(facts["truncated"], "a closed quote followed by ... is a cut string")
        self.assertEqual(facts["status"], "INCOMPLETE")

    def test_an_abbreviated_array_is_reported(self):
        text = (
            'execve("/usr/bin/python3", ["python3", "arg0", "arg1", ...], '
            '["PATH=/usr/bin"]) = 0'
        )
        facts = scan(text, [SECRET])
        self.assertTrue(facts["abbreviated"], "a bare ... element is an abbreviated array")
        self.assertEqual(facts["status"], "INCOMPLETE")

    def test_escaped_argv_bytes_are_decoded_before_the_scan(self):
        # strace escapes the quote, the backslash and the newline; a scan of the
        # rendered text would miss a secret that contains any of them.
        escaped = SECRET.replace(SECRET[:2], 'a"b\\c')
        rendered = escaped.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        text = (
            f'execve("/usr/bin/env", ["env", "SECRET_KEY={rendered}"], []) = 0'
        )
        facts = scan(text, [escaped])
        self.assertTrue(facts["secret_found"], "the escaped form hides the secret from a text scan")
        self.assertEqual(facts["status"], "FAIL")

    def test_a_secret_only_in_envp_is_not_a_finding(self):
        text = exec_line(["ssh", "root@10.89.0.12"], env=(f"SECRET_KEY={SECRET}",))
        facts = scan(text, [SECRET])
        self.assertFalse(facts["secret_found"], "envp is discarded, and the case says so")
        self.assertEqual(facts["status"], "PASS")

    def test_a_base64_encoded_secret_in_argv_is_a_finding(self):
        encoded = base64.b64encode(SECRET.encode()).decode()
        text = exec_line(["ssh", f"SECRET_KEY={encoded}"])
        facts = scan(text, [SECRET])
        self.assertTrue(facts["secret_found"], "an encoded form is a known encoding of the secret")
        self.assertEqual(facts["status"], "FAIL")

    def test_an_unpadded_urlsafe_encoding_is_a_finding(self):
        encoded = base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip("=")
        text = exec_line(["ssh", f"payload={encoded}"])
        self.assertTrue(scan(text, [SECRET])["secret_found"])

    def test_a_record_split_by_interleaving_is_rejoined(self):
        # -f merges the records of concurrent processes, so one exec can arrive
        # as two halves. Dropping either half would hide an exec from the scan.
        text = "\n".join((
            f'42  execve("/usr/bin/ssh", ["ssh", "-o", "BatchMode=yes"]{argv_probe.UNFINISHED}',
            '43  execve("/usr/bin/true", ["true"], []) = 0',
            "42  <... execve resumed>, []) = 0",
        ))
        parsed = argv_probe.parse_records(text)
        self.assertEqual(parsed["errors"], [])
        self.assertEqual([record["syscall"] for record in parsed["records"]], ["execve", "execve"])
        self.assertEqual(parsed["records"][1]["argv"], ["ssh", "-o", "BatchMode=yes"])

    def test_a_trace_ending_inside_a_record_is_incomplete(self):
        text = f'42  execve("/usr/bin/ssh", ["ssh", "-o"]{argv_probe.UNFINISHED}'
        facts = scan(text, [SECRET])
        self.assertEqual(facts["status"], "INCOMPLETE")
        self.assertTrue(any("ends inside" in error for error in facts["errors"]))

    def test_a_trace_with_no_exec_record_is_incomplete(self):
        facts = scan("+++ exited with 0 +++", [SECRET])
        self.assertEqual(facts["status"], "INCOMPLETE")
        self.assertEqual(facts["exec_count"], 0)

    def test_absence_without_a_secret_is_incomplete(self):
        facts = scan(exec_line(["ssh", "root@10.89.0.12"]), [])
        self.assertFalse(facts["secret_found"])
        self.assertEqual(facts["status"], "INCOMPLETE", "nothing to look for is not a clean trace")

    def test_a_scan_without_a_known_client_is_incomplete(self):
        # Without the client's name the remote dispatch cannot be found, so a
        # trace that never shows one would otherwise read as a clean dispatch.
        facts = scan(exec_line(["ssh", "root@10.89.0.12"]), [SECRET], client="")
        self.assertEqual(facts["ssh_execs"], 0)
        self.assertEqual(facts["status"], "INCOMPLETE")
        self.assertTrue(any("dispatches through" in error for error in facts["errors"]))

    def test_both_syscalls_are_counted_separately(self):
        text = "\n".join((
            exec_line(["python3", "-c", "pass"]),
            exec_line(["python3", "-c", "pass"], syscall="execveat"),
        ))
        facts = scan(text, [SECRET])
        self.assertEqual((facts["execve_count"], facts["execveat_count"]), (1, 1))

    def test_a_missing_trace_file_is_incomplete_and_not_removed(self):
        facts = argv_probe.scan_trace_file("/run/gowave_e2e_strace/absent.trace", [SECRET], SSH_CLIENT)
        self.assertEqual(facts["status"], "INCOMPLETE")
        self.assertFalse(facts["trace_removed"])
        self.assertEqual(facts["trace_bytes"], 0)


class TestAcceptanceFixtures(unittest.TestCase):
    """The observer must see a sentinel whole before its verdict is worth reading."""

    LIMIT = 131072

    def traces(self, **overrides):
        sentinel = argv_probe.SENTINEL_AFTER_32
        many = list(argv_probe.MANY_ARGUMENTS)
        complete = {
            "long-argument-execve": exec_line(["python3", "-c", "pass", sentinel]),
            "long-argument-execveat": exec_line(
                ["python3", "-c", "pass", sentinel], syscall="execveat",
            ),
            "long-argument-limit-control": (
                'execve("/usr/bin/python3", ["python3", "-c", "pass", '
                f'"{(("A" * 32) + sentinel)[:32]}"...], []) = 0'
            ),
            "many-arguments-execve": exec_line(["python3", "-c", "pass", *many]),
        }
        complete.update(overrides)
        return complete

    def test_a_complete_set_of_legs_passes(self):
        facts = argv_probe.judge_fixtures(self.LIMIT, self.traces())
        self.assertEqual(facts["status"], "PASS", facts["errors"])
        self.assertEqual([leg["status"] for leg in facts["fixtures"]], ["PASS"] * 4)

    def test_a_long_argument_that_was_cut_fails_its_leg(self):
        cut = (
            'execve("/usr/bin/python3", ["python3", "-c", "pass", '
            f'"{(("A" * 32) + argv_probe.SENTINEL_AFTER_32)[:32]}"...], []) = 0'
        )
        facts = argv_probe.judge_fixtures(self.LIMIT, self.traces(**{"long-argument-execve": cut}))
        self.assertEqual(facts["status"], "FAIL")
        self.assertIn("long-argument-execve", " ".join(facts["errors"]))

    def test_a_missing_execveat_leg_fails(self):
        facts = argv_probe.judge_fixtures(
            self.LIMIT, self.traces(**{"long-argument-execveat": exec_line(["true"])}),
        )
        self.assertEqual(facts["status"], "FAIL")
        self.assertIn("long-argument-execveat", " ".join(facts["errors"]))

    def test_a_control_that_keeps_the_sentinel_fails(self):
        kept = exec_line(["python3", "-c", "pass", argv_probe.SENTINEL_AFTER_32])
        facts = argv_probe.judge_fixtures(
            self.LIMIT, self.traces(**{"long-argument-limit-control": kept}),
        )
        self.assertEqual(facts["status"], "FAIL")
        self.assertIn("32-byte limit", " ".join(facts["errors"]))

    def test_a_control_without_a_truncation_marker_fails(self):
        silent = exec_line(["python3", "-c", "pass", "A" * 32])
        facts = argv_probe.judge_fixtures(
            self.LIMIT, self.traces(**{"long-argument-limit-control": silent}),
        )
        self.assertEqual(facts["status"], "FAIL")
        self.assertIn("no truncation marker", " ".join(facts["errors"]))

    def test_an_abbreviated_many_element_leg_fails(self):
        abbreviated = (
            'execve("/usr/bin/python3", ["python3", "-c", "pass", "arg0", ...], []) = 0'
        )
        facts = argv_probe.judge_fixtures(
            self.LIMIT, self.traces(**{"many-arguments-execve": abbreviated}),
        )
        self.assertEqual(facts["status"], "FAIL")
        self.assertIn("many-arguments-execve", " ".join(facts["errors"]))

    def test_elements_out_of_order_fail_even_when_the_sentinel_is_last(self):
        out_of_order = list(argv_probe.MANY_ARGUMENTS)
        out_of_order[0], out_of_order[1] = out_of_order[1], out_of_order[0]
        facts = argv_probe.judge_fixtures(
            self.LIMIT,
            self.traces(**{"many-arguments-execve": exec_line(["python3", "-c", "pass", *out_of_order])}),
        )
        self.assertEqual(facts["status"], "FAIL")
        self.assertIn("in that order", " ".join(facts["errors"]))

    def test_the_limit_is_32_pages(self):
        self.assertEqual(argv_probe.trace_limit(4096), 131072)
        self.assertEqual(argv_probe.trace_limit(65536), 2097152)


class _FakePodman:
    """A Podman stand-in that answers the observer's four questions."""

    def __init__(self, *, strace_present=True, install_fails=False, secret=SECRET, client=SSH_CLIENT):
        self.strace_present = strace_present
        self.install_fails = install_fails
        self.secret = secret
        self.client = client
        self.bash_calls = []
        self.exec_calls = []

    def exec(self, name, argv, check=True, input_text=None, timeout=None):
        self.exec_calls.append({"name": name, "argv": list(argv), "input": input_text})
        if argv[:2] == ["bash", "-lc"] and "command -v strace" in argv[-1]:
            return _result(0 if self.strace_present else 1)
        if argv[:2] == ["python3", "scan"] or (len(argv) > 1 and argv[1] == "scan"):
            return _result(0, '{"status": "PASS"}\n')
        return _result(0)

    def exec_bash(self, name, script, check=True, input_text=None, timeout=None):
        self.bash_calls.append({"name": name, "script": script, "input": input_text})
        if "apt-get install" in script:
            return _result(1 if self.install_fails else 0, stderr="E: Unable to fetch some archives")
        if "strace -V" in script:
            return _result(0, "strace -- version 6.8\n")
        if "trace=execve,execveat true" in script:
            return _result(0)
        if "SC_PAGE_SIZE" in script:
            return _result(0, "131072\n")
        if "command -v ssh" in script:
            return _result(0 if self.client else 1, self.client + "\n" if self.client else "")
        if "extract_secret_key" in script:
            return _result(0 if self.secret else 1, self.secret, stderr="no secret")
        if script.startswith("cat > "):
            return _result(0)
        return _result(0)


def _result(returncode, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestObserverWiring(unittest.TestCase):
    """The observer is installed, delivered and read over stdin, never argv."""

    def test_the_trace_command_is_the_one_the_live_runner_uses(self):
        prefix = argv_probe.strace_prefix(argv_probe.TRACE_PATH, 131072)
        for token in ("strace", "-f", "-v", "-s 131072", "trace=execve,execveat"):
            self.assertIn(token, prefix)
        self.assertIn(argv_probe.TRACE_PATH, prefix)

    def test_an_absent_strace_is_installed_and_the_limit_read_from_the_master(self):
        podman = _FakePodman(strace_present=False)
        facts = argv_probe.ensure_strace(podman, "master")
        self.assertTrue(facts["ok"], facts["error"])
        self.assertTrue(facts["installed"])
        self.assertEqual(facts["limit"], 131072)
        self.assertIn("6.8", facts["version"])
        self.assertTrue(any("apt-get install" in call["script"] for call in podman.bash_calls))

    def test_an_install_that_fails_is_reported_rather_than_raised(self):
        facts = argv_probe.ensure_strace(_FakePodman(strace_present=False, install_fails=True), "master")
        self.assertFalse(facts["ok"])
        self.assertIn("could not be installed", facts["error"])

    def test_a_master_that_resolves_no_client_is_reported_rather_than_raised(self):
        facts = argv_probe.ensure_strace(_FakePodman(client=""), "master")
        self.assertFalse(facts["ok"])
        self.assertEqual(facts["client"], "")
        self.assertIn("resolves no client", facts["error"])

    def test_the_observer_source_travels_over_stdin(self):
        podman = _FakePodman()
        result = argv_probe.deliver(podman, "master")
        self.assertTrue(result["delivered"], result["error"])
        writes = [call for call in podman.bash_calls if call["script"].startswith("cat > ")]
        self.assertEqual(len(writes), 1)
        self.assertIn("def scan_trace_text", writes[0]["input"], "the file is streamed, not passed as argv")
        self.assertNotIn("def scan_trace_text", writes[0]["script"])

    def test_the_secret_reaches_the_scanner_over_stdin_only(self):
        podman = _FakePodman()
        argv_probe.scan(podman, "master", SECRET, SSH_CLIENT)
        scanned = [call for call in podman.exec_calls if "scan" in call["argv"]]
        self.assertEqual(len(scanned), 1)
        self.assertEqual(scanned[0]["input"], SECRET)
        self.assertNotIn(SECRET, " ".join(scanned[0]["argv"]))
        self.assertIn(SSH_CLIENT, scanned[0]["argv"],
                      "the client the Master named travels as an argument, not as a secret")

    def test_the_secret_is_read_through_the_products_own_extractor(self):
        podman = _FakePodman()
        secret, error = argv_probe.extract_secret(podman, "master")
        self.assertEqual((secret, error), (SECRET, ""))
        self.assertIn("modules/node.sh", " ".join(call["script"] for call in podman.bash_calls))

    def test_a_master_that_cannot_print_its_secret_reports_why(self):
        secret, error = argv_probe.extract_secret(_FakePodman(secret=""), "master")
        self.assertEqual(secret, "")
        self.assertIn("could not print", error)


class _StubHost:
    """The pieces ``node_add`` touches, so the real function can be exercised."""

    def __init__(self, podman):
        self.podman = podman
        self.target_name = "master"
        self.argv_observer = None
        self.context = types.SimpleNamespace(
            evidence_text=lambda name, text: None,
        )

    def node_add_script(self, name):
        return f"bash /repo/gowave-auto.sh node add '{name}' '10.89.0.12' 'worker.testbed.internal'"


class TestNodeAddIsTraced(unittest.TestCase):
    """The dispatch the case reads is the operator's real one, under strace."""

    def test_the_dispatch_runs_under_the_observer(self):
        podman = _FakePodman()
        host = _StubHost(podman)
        outcome = topology.MultiNodeTopology.node_add(host, "worker-1")
        self.assertEqual(outcome.returncode, 0)
        self.assertTrue(host.argv_observer["ok"])
        scripts = [call["script"] for call in podman.bash_calls]
        traced = [
            script for script in scripts
            if script.startswith("strace -f -v ") and "gowave-auto.sh node add" in script
        ]
        self.assertEqual(len(traced), 1, "the operator command is wrapped exactly once")
        self.assertIn("gowave-auto.sh node add", traced[0])
        self.assertEqual(outcome.command, traced[0])
        prepared = [script for script in scripts if script.startswith("mkdir -p -m 0700")]
        self.assertEqual(len(prepared), 1, "the trace directory is prepared before the trace")

    def test_an_unusable_observer_still_runs_the_deployment_untraced(self):
        podman = _FakePodman(strace_present=False, install_fails=True)
        host = _StubHost(podman)
        outcome = topology.MultiNodeTopology.node_add(host, "worker-1")
        self.assertEqual(outcome.returncode, 0)
        self.assertFalse(host.argv_observer["ok"])
        self.assertNotIn("strace", outcome.command, "an unobserved deployment is still a deployment")
        self.assertIn("gowave-auto.sh node add", outcome.command)


class TestArgvObserverCase(unittest.TestCase):
    """WRK-01..03 fail on every trace that is not complete and secret-free.

    The case reads four answers — the observer state the deployment recorded, the
    delivery, the fixtures and the scan — and accepts only one combination. Each
    answer is replaced here, so a clause that stopped refusing its own failure
    cannot pass as an observation.
    """

    OBSERVER = {"ok": True, "installed": True, "version": "strace -- version 6.8",
                "limit": 131072, "client": SSH_CLIENT, "error": ""}
    DELIVERED = {"delivered": True, "path": argv_probe.PROBE_PATH, "error": ""}
    FIXTURES = {"status": "PASS", "errors": [], "fixtures": [], "limit": 131072}
    VERDICT = {
        "status": "PASS", "exec_count": 41, "execve_count": 40, "execveat_count": 1,
        "ssh_execs": 2, "secret_found": False, "truncated": False, "abbreviated": False,
        "trace_bytes": 19431, "trace_removed": True, "errors": [],
    }

    def evidence(self, *, observer=None, delivered=None, fixtures=None,
                 secret=SECRET, secret_error="", verdict=None):
        product = types.SimpleNamespace(podman=object())
        observed = self.OBSERVER if observer is None else observer
        product.require_worker = lambda: types.SimpleNamespace(
            argv_observer=observed, target_name="master",
        )
        answers = {
            "deliver": dict(self.DELIVERED) if delivered is None else delivered,
            "run_fixtures": dict(self.FIXTURES) if fixtures is None else fixtures,
            "extract_secret": (secret, secret_error),
            "scan": dict(self.VERDICT) if verdict is None else verdict,
        }
        with contextlib.ExitStack() as stack:
            for name, answer in answers.items():
                stack.enter_context(
                    unittest.mock.patch.object(
                        argv_probe, name, lambda *_, answer=answer, **__: answer,
                    )
                )
            return multi_node.case_argv_observer(product)

    def test_a_complete_observation_returns_the_counts_and_no_secret(self):
        evidence = self.evidence()
        self.assertEqual(evidence["argv_observer_exec_count"], 41)
        self.assertEqual(evidence["argv_observer_execveat_count"], 1)
        self.assertEqual(evidence["argv_observer_ssh_execs"], 2)
        self.assertIs(evidence["argv_observer_secret_found"], False)
        self.assertIs(evidence["argv_observer_trace_removed"], True)
        self.assertEqual(evidence["argv_observer_strace_version"], "strace -- version 6.8")
        self.assertEqual(evidence["argv_observer_ssh_client"], SSH_CLIENT)

    def test_an_incomplete_scan_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.evidence(verdict={**self.VERDICT, "status": "INCOMPLETE",
                                   "errors": ["the trace ends inside 1 exec record(s)"]})
        self.assertIn("the dispatch trace is INCOMPLETE", str(caught.exception))

    def test_a_secret_that_reached_argv_is_refused(self):
        # The clause does not trust the verdict: a scan that reported PASS while
        # flagging the secret is still refused, so an inverted status cannot pass
        # a trace the scanner itself called a finding.
        with self.assertRaises(AssertionError) as caught:
            self.evidence(verdict={**self.VERDICT, "secret_found": True})
        self.assertIn("carries the Master's SECRET_KEY", str(caught.exception))

    def test_a_trace_without_the_ssh_client_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.evidence(verdict={**self.VERDICT, "ssh_execs": 0})
        self.assertIn("did not cover the deployment's own remote dispatch", str(caught.exception))

    def test_a_trace_left_on_the_master_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.evidence(verdict={**self.VERDICT, "trace_removed": False})
        self.assertIn("the trace carrying envp was not removed", str(caught.exception))

    def test_fixtures_that_fail_are_refused_before_the_trace_is_read(self):
        with self.assertRaises(AssertionError) as caught:
            self.evidence(fixtures={"status": "FAIL", "fixtures": [],
                                    "errors": ["long-argument-execveat: no execveat record"]})
        self.assertIn("failed its own acceptance fixtures", str(caught.exception))

    def test_an_unusable_observer_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.evidence(observer={"ok": False, "error": "strace could not be installed"})
        self.assertIn("was not usable", str(caught.exception))

    def test_a_master_that_cannot_print_its_secret_is_refused(self):
        with self.assertRaises(AssertionError) as caught:
            self.evidence(secret="", secret_error="the Master could not print its own SECRET_KEY")
        self.assertIn("could not print its own SECRET_KEY", str(caught.exception))


class TestObserverDocumentation(unittest.TestCase):
    """The page states what this observer sees, and the catalog says the same.

    A page that described a wider observation than the probe makes would be the
    same defect as an observer that cannot see a sentinel: a claim without a
    mechanism behind it.
    """

    HEADING = "## How the Master's own command line is observed"

    def section(self):
        page = (REPO_ROOT / "docs" / "PODMAN_E2E_DISCOVERY.md").read_text(encoding="utf-8")
        start = page.index(self.HEADING)
        return page[start : page.index("\n## ", start + len(self.HEADING))]

    def test_every_case_the_observer_answers_is_named_by_the_page(self):
        from tools.podman_e2e import catalog as case_catalog

        observed = {
            case_id
            for case_id, observers in case_catalog.LIVE_PARITY_OBSERVERS.items()
            if observers.get("multi-node") == multi_node.ARGV_OBSERVER_CASE_ID
        }
        self.assertEqual(observed, {"WRK-01", "WRK-02", "WRK-03"})
        section = self.section()
        for case_id in sorted(observed) + [multi_node.ARGV_OBSERVER_CASE_ID]:
            self.assertIn(case_id, section, "the page stopped naming a case this observer answers")

    def test_the_catalogued_assertion_is_the_one_the_probe_implements(self):
        from tools.podman_e2e import catalog as case_catalog

        entry = {
            case["id"]: case for case in case_catalog.load_catalog()["cases"]
        }[multi_node.ARGV_OBSERVER_CASE_ID]
        self.assertEqual(entry["environment"], "container")
        for token in ("execve", "execveat", "PAGE_SIZE"):
            self.assertIn(token, entry["assertion"])

    def test_the_page_states_the_limit_the_probe_computes(self):
        self.assertEqual(argv_probe.LIMIT_FACTOR, 32)
        self.assertIn('32 * os.sysconf("SC_PAGE_SIZE")', " ".join(self.section().split()))

    def test_the_page_names_what_the_observation_cannot_reach(self):
        prose = " ".join(self.section().split())
        self.assertIn("beyond the SSH boundary", prose)
        self.assertIn("`envp`", prose)
        self.assertIn("only counts come back", prose)
        self.assertIn("removed inside the container", prose)

    def test_the_page_says_an_unobserved_deployment_is_still_a_deployment(self):
        prose = " ".join(self.section().split())
        self.assertIn("runs untraced", prose)
        self.assertIn("`WRK-04` still judges", prose)


if __name__ == "__main__":
    unittest.main()
