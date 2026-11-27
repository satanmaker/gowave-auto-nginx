#!/usr/bin/env python3
"""Suite nonroot: a preserved host carries the packages the run installed.

``HOOK-04`` is §Global Certbot Deploy Hook Ownership in
``openspec/specs/podman-e2e/spec.md``: when the
installation transaction has installed or upgraded OS packages and their
post-install scripts have created service defaults, and compensation or teardown
completes under ``TEST_TEARDOWN_POLICY=PRESERVE``, the report records the
package changes as retained residual state and distinguishes transaction
compensation from restoration of the original OS baseline.

The record is ``record_worker_package_baseline`` and
``record_worker_package_changes`` in ``gowave-node-auto.sh``: the baseline is
taken while the journal's directory is the only thing written, the delta once
every package-mutating step is behind the transaction, and both land in the
transaction's own recovery directory, atomic and mode 0600. The reader is
``read_package_changes`` in ``tools/live_vps/teardown.py``, and the verdict is
``execute_teardown`` under PRESERVE: packages retained, no baseline restored,
the host not eligible for another clean-baseline run, and ``unrecorded`` when
the run left no record at all.

The case drives those functions over a scratch root with a stub package manager,
so it decides the bytes the shell wrote and the report the shipped teardown
gives for them. Each clause is damaged on its own — a record outside the
transaction, one readable by every user, a delta that loses an install, an
upgrade or a removal, a package manager that could not answer recorded as no
change, a baseline outside its journal, changes without a baseline, and five
teardown clauses — so every assertion is seen to fail for the reason it
protects.
"""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import catalog, package_residual  # noqa: E402
from tools.podman_e2e.runner import CaseBlocked  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")
DRIVERS = {
    "aio": package_residual.case_panel_package_residuals,
    "multi-node": package_residual.case_worker_package_residuals,
}

#: The record block is spliced into the top-level library, the payload and the
#: rollback script, so a damage rewrites every copy — and the copies stay
#: byte-identical.
BLOCK_COPIES = 3

#: What each damage is meant to make the case say, so a probe that went red on
#: an unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "baseline-is-world-readable": "the package baseline is readable by every user",
    "changes-are-world-readable": "the package change record is readable by every user",
    "changes-miss-the-installed-package":
        "a package the transaction installed is missing from the record",
    "changes-ignore-the-upgrade":
        "a package the transaction upgraded is recorded without the version it came from",
    "changes-miss-the-removed-package":
        "a package the transaction removed is missing from the record",
    "unavailable-is-recorded-as-no-change":
        "a package manager that could not answer was recorded as no package change",
    "baseline-is-written-outside-the-journal":
        "a package baseline was written for a transaction with no journal directory",
    "changes-without-a-baseline-are-claimed":
        "package changes were claimed for a transaction that recorded no baseline",
    "preserve-claims-a-restored-baseline":
        "PRESERVE claimed to have restored an OS baseline it never touched",
    "preserve-calls-the-host-eligible":
        "PRESERVE left the host eligible for another clean-baseline run",
    "preserve-drops-the-residual-packages":
        "PRESERVE did not report the packages the transaction installed as retained state",
    "preserve-invents-a-clean-record":
        "a teardown handed no package record claimed to know the package change",
    "reader-accepts-an-unknown-kind":
        "a package record that does not match the documented shape was parsed anyway",
    "reader-accepts-a-short-row":
        "a package record that does not match the documented shape was parsed anyway",
    "reader-accepts-a-foreign-field":
        "a package record that does not match the documented shape was parsed anyway",
}

#: The functions the block the three copies share is made of.
RECORD_FUNCTIONS = (
    "worker_package_record_dir() {",
    "worker_package_inventory() {",
    "record_worker_package_baseline() {",
    "record_worker_package_changes() {",
)

_BASELINE_GUARD = (
    '    if [[ ! -d "$directory" ]]; then\n'
    '        echo "Error: The transaction directory $directory is absent, so a package '
    'baseline would not belong to a journal." >&2\n'
    '        return 1\n'
    '    fi\n'
)

_CHANGES_GUARD = (
    '    if [[ ! -f "$before" ]]; then\n'
    '        echo "Error: The package baseline for $transaction is absent, so the package '
    'changes it caused cannot be stated." >&2\n'
    '        return 1\n'
    '    fi\n'
)

#: The teardown clauses, rewritten in the shipped reader and the PRESERVE branch.
_TEARDOWN_DAMAGES = {
    "preserve-claims-a-restored-baseline": (
        '            "restored_baseline": False,\n',
        '            "restored_baseline": True,\n',
    ),
    "preserve-calls-the-host-eligible": (
        '            "clean_baseline_eligible": False,\n',
        '            "clean_baseline_eligible": True,\n',
    ),
    "preserve-drops-the-residual-packages": (
        '            "residual_state": {"packages": packages, "retained": True},\n',
        '            "residual_state": {"retained": True},\n',
    ),
    "preserve-invents-a-clean-record": (
        '            else {"inventory": "unrecorded", "installed": [], "upgraded": [], '
        '"removed": []}\n',
        '            else {"inventory": "recorded", "installed": [], "upgraded": [], '
        '"removed": []}\n',
    ),
    "reader-accepts-an-unknown-kind": (
        '        if kind not in ("installed", "upgraded", "removed"):\n'
        '            raise ValueError(f"{path}:{number}: {kind!r} is not a package change")\n',
        '        if kind not in ("installed", "upgraded", "removed"):\n'
        '            kind = "installed"\n',
    ),
    "reader-accepts-a-short-row": (
        '        if len(fields) != expected:\n'
        '            raise ValueError(\n'
        '                f"{path}:{number}: a {kind} row carries {len(fields)} fields, '
        'not {expected}")\n',
        '        if len(fields) < expected:\n'
        '            fields = fields + ["0"] * (expected - len(fields))\n',
    ),
    "reader-accepts-a-foreign-field": (
        '            if not _PACKAGE_FIELD.match(field):\n',
        '            if False:\n',
    ),
}


class _LocalHost:
    """The container's shell, answered by this machine: same script, same bash."""

    def host_script(self, script, timeout=180):
        return subprocess.run(
            ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
        )


class _LocalPodman:
    def exec_bash(self, name, script, check=True, input_text=None, timeout=180):
        return subprocess.run(
            ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
        )


class _LocalProduct:
    def __init__(self, worker=True):
        self.host_script = _LocalHost().host_script
        self.podman = _LocalPodman()
        self.topology = (
            type("Topology", (), {"worker_name": "worker-1"})() if worker else None
        )


def _rewritten(source: Path, old: str, new: str, expected: int) -> str:
    """The file's text with exactly ``expected`` occurrences rewritten."""
    body = source.read_text(encoding="utf-8")
    assert body.count(old) == expected, f"{old!r} occurs {body.count(old)} times, not {expected}"
    return body.replace(old, new)


def _damaged_teardown(damage, workdir):
    """The shipped teardown with one clause rewritten, loaded as the real module name."""
    source = Path(package_residual.live_teardown.__file__)
    old, new = _TEARDOWN_DAMAGES[damage]
    broken = Path(workdir) / f"teardown-{damage}.py"
    broken.write_text(_rewritten(source, old, new, 1), encoding="utf-8")
    name = "tools.live_vps.teardown"
    saved = sys.modules.get(name)
    spec = importlib.util.spec_from_file_location(name, str(broken))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if saved is None:
            del sys.modules[name]
        else:
            sys.modules[name] = saved
    return module


def _damage_source(damage):
    """The product with one clause of the package record rewritten."""
    source = package_residual.WORKER_INSTALLER

    if damage == "baseline-is-world-readable":
        return _rewritten(
            source,
            '    if ! chmod 0600 -- "$temporary" || ! sync "$temporary" ||\n',
            '    if ! chmod 0644 -- "$temporary" || ! sync "$temporary" ||\n',
            BLOCK_COPIES,
        )
    if damage == "changes-are-world-readable":
        return _rewritten(
            source,
            '    if ! chmod 0600 -- "$changes" || ! sync "$changes" ||\n',
            '    if ! chmod 0644 -- "$changes" || ! sync "$changes" ||\n',
            BLOCK_COPIES,
        )
    if damage == "changes-miss-the-installed-package":
        return _rewritten(
            source,
            '                        if (!(name in before)) print "installed\\t" name "\\t" after[name]\n',
            "                        if (!(name in before)) { }\n",
            BLOCK_COPIES,
        )
    if damage == "changes-ignore-the-upgrade":
        return _rewritten(
            source,
            '                        else if (before[name] != after[name]) print "upgraded\\t" '
            'name "\\t" before[name] "\\t" after[name]\n',
            '                        else if (0) print "upgraded\\t" name "\\t" before[name] '
            '"\\t" after[name]\n',
            BLOCK_COPIES,
        )
    if damage == "changes-miss-the-removed-package":
        return _rewritten(
            source,
            '                    for (name in before) if (!(name in after)) print "removed\\t" '
            'name "\\t" before[name]\n',
            '                    for (name in before) if (0) print "removed\\t" name "\\t" '
            'before[name]\n',
            BLOCK_COPIES,
        )
    if damage == "unavailable-is-recorded-as-no-change":
        return _rewritten(
            source,
            '        printf \'%s\\n\' "#unavailable" >"$temporary"\n',
            "        :\n",
            BLOCK_COPIES,
        )
    if damage == "baseline-is-written-outside-the-journal":
        return _rewritten(
            source,
            _BASELINE_GUARD,
            '    if [[ ! -d "$directory" ]]; then\n        mkdir -p "$directory"\n    fi\n',
            BLOCK_COPIES,
        )
    if damage == "changes-without-a-baseline-are-claimed":
        return _rewritten(
            source,
            _CHANGES_GUARD,
            '    if false; then\n'
            '        echo "Error: The package baseline for $transaction is absent, so the '
            'package changes it caused cannot be stated." >&2\n'
            '        return 1\n'
            '    fi\n',
            BLOCK_COPIES,
        )
    raise AssertionError(f"unknown damage {damage!r}")


def run_case(topology_name, damage=None, workdir=None):
    """Run one contour, optionally with one damaged clause of the product."""
    product = _LocalProduct(worker=topology_name == "multi-node")
    patchers = []
    if damage in _TEARDOWN_DAMAGES:
        patchers.append(mock.patch.object(
            package_residual, "live_teardown", _damaged_teardown(damage, workdir)))
    elif damage:
        broken = Path(workdir) / "gowave-node-auto-damaged.sh"
        broken.write_text(_damage_source(damage), encoding="utf-8")
        patchers.append(mock.patch.object(package_residual, "WORKER_INSTALLER", broken))
    for patcher in patchers:
        patcher.start()
    try:
        return DRIVERS[topology_name](product, object()), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class TestPackageResidualRegistration(unittest.TestCase):
    """The id is registered on both contours, each with the driver it runs."""

    def test_the_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        self.assertIn(package_residual.CASE_ID, registry)
        self.assertEqual(set(registry[package_residual.CASE_ID]), set(TOPOLOGIES))
        for name, function in DRIVERS.items():
            self.assertEqual(
                registry[package_residual.CASE_ID][name]["driver"],
                f"package_residual:{function.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[package_residual.CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[package_residual.CASE_ID])
        self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestPackageResidualCase(unittest.TestCase):
    """Both halves hold on this tree, and each reports the facts it decides."""

    def test_the_record_holds_on_both_contours(self):
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(len(facts), len(package_residual.EVIDENCE))
                self.assertTrue(all(facts.values()), facts)

    def test_the_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for name in TOPOLOGIES:
            with self.subTest(topology=name):
                facts, refusal = run_case(name)
                self.assertIsNone(refusal)
                self.assertEqual(
                    sorted(facts), registry[package_residual.CASE_ID][name]["evidence"])

    def test_all_three_copies_of_the_block_agree(self):
        body = package_residual.WORKER_INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(body.count(package_residual.BLOCK_BANNER), BLOCK_COPIES)
        reference = package_residual.record_block_body()
        for signature in RECORD_FUNCTIONS:
            self.assertIn(signature, reference)
        self.assertEqual(body.count(reference), BLOCK_COPIES)

    def test_the_record_belongs_to_its_transaction(self):
        body = package_residual.WORKER_INSTALLER.read_text(encoding="utf-8")
        # One directory per transaction, so a record never outlives the journal
        # it belongs to or answers for another transaction's packages.
        self.assertEqual(
            body.count('    printf \'%s\\n\' "${root%/}/recovery/${transaction}"\n'),
            BLOCK_COPIES,
        )

    def test_the_baseline_is_written_after_the_journal_and_before_the_first_mutation(self):
        body = package_residual.WORKER_INSTALLER.read_text(encoding="utf-8")
        captured = '    record_worker_package_baseline "$_ACME_TX_ID" || return 1\n'
        self.assertEqual(body.count(captured), 1)
        written = body.index(captured)
        # The baseline and the journal name the same transaction: a record that
        # outlives its journal is a record of nothing.
        self.assertLess(
            body.index('    record_worker_transaction_journal "$_ACME_TX_ID" || return 1\n'),
            written,
        )
        for mutation in ("    setup_system_prereqs </dev/null\n",
                         "    configure_host_security </dev/null\n",
                         "    configure_firewall </dev/null\n",
                         "    unpack_cover_reality </dev/null\n",
                         "    configure_edge_nginx \"$_WORKER_LIVE_DIR\" \"$_REALITY_LIVE_DIR\" \"${_VISION_LIVE_DIR:-}\" </dev/null\n",
                         "    SECRET_KEY=\"$_NODE_SECRET_KEY\" run_upstream_node_installer </dev/null\n"):
            with self.subTest(mutation=mutation):
                self.assertLess(written, body.index(mutation))

    def test_the_changes_are_written_before_the_install_claims_its_paths(self):
        body = package_residual.WORKER_INSTALLER.read_text(encoding="utf-8")
        changes = '    record_worker_package_changes "$_ACME_TX_ID" || return 1\n'
        self.assertEqual(body.count(changes), 1)
        written = body.index(changes)
        self.assertLess(
            body.index(
                "    SECRET_KEY=\"$_NODE_SECRET_KEY\" run_upstream_node_installer </dev/null\n"),
            written,
        )
        self.assertLess(written, body.index("    record_worker_mutation_targets\n"))
        self.assertLess(
            written,
            body.index('    mark_worker_transaction_state installed "$_ACME_TX_ID" || return 1\n'),
        )

    def test_a_compensation_records_the_residue_before_it_restores_paths(self):
        body = package_residual.WORKER_INSTALLER.read_text(encoding="utf-8")
        residue = '    record_worker_package_changes "$_ACME_TX_ID" "$state_root" ||\n'
        self.assertEqual(body.count(residue), 1)
        recorded = body.index(residue)
        # A run refused before its first mutation captured no before-image, so
        # it exits early and has no package change to state; one that did get
        # that far records the residue before the paths are put back.
        self.assertLess(
            body.index("No Worker before-image was captured; nothing to compensate."),
            recorded,
        )
        self.assertLess(body.index("compensate_remote_worker() {"), recorded)
        self.assertLess(
            recorded,
            body.index('    restore_worker_targets_before_image \\\n'
                       '        "$host_root" "$(worker_targets_before_image "$state_root" '
                       '"$_ACME_TX_ID")" ||\n'
                       '        rollback_failed=1\n', recorded),
        )
        self.assertIn(
            "[ROLLBACK] The package changes this transaction caused could not be recorded",
            body[recorded:body.index("    # 1. Stop and remove GoWave Node and Xray systemd "
                                     "services\n")],
        )

    def test_every_evidence_key_has_a_sentence(self):
        self.assertEqual(sorted(package_residual._SENTENCES), sorted(package_residual.EVIDENCE))

    def test_a_contour_without_a_worker_is_blocked_not_passed(self):
        product = _LocalProduct(worker=False)
        with self.assertRaises(CaseBlocked):
            DRIVERS["multi-node"](product, object())


class TestPackageResidualDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory(prefix="gowave-package-damage-")
        self.addCleanup(self._directory.cleanup)
        self.workdir = Path(self._directory.name)

    def assert_refused(self, damage, topology_name="multi-node"):
        _, refusal = run_case(topology_name, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make HOOK-04 refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_baseline_readable_by_every_user_is_refused(self):
        self.assert_refused("baseline-is-world-readable", "aio")

    def test_changes_readable_by_every_user_are_refused(self):
        self.assert_refused("changes-are-world-readable")

    def test_changes_that_miss_an_install_are_refused(self):
        self.assert_refused("changes-miss-the-installed-package")

    def test_changes_that_ignore_an_upgrade_are_refused(self):
        self.assert_refused("changes-ignore-the-upgrade", "aio")

    def test_changes_that_miss_a_removal_are_refused(self):
        self.assert_refused("changes-miss-the-removed-package")

    def test_a_package_manager_that_could_not_answer_is_refused(self):
        self.assert_refused("unavailable-is-recorded-as-no-change")

    def test_a_baseline_outside_its_journal_is_refused(self):
        self.assert_refused("baseline-is-written-outside-the-journal")

    def test_changes_without_a_baseline_are_refused(self):
        self.assert_refused("changes-without-a-baseline-are-claimed")

    def test_a_preserve_that_claims_a_restored_baseline_is_refused(self):
        self.assert_refused("preserve-claims-a-restored-baseline")

    def test_a_preserve_that_leaves_the_host_eligible_is_refused(self):
        self.assert_refused("preserve-calls-the-host-eligible", "aio")

    def test_a_preserve_that_drops_the_packages_is_refused(self):
        self.assert_refused("preserve-drops-the-residual-packages")

    def test_a_preserve_that_invents_a_clean_record_is_refused(self):
        self.assert_refused("preserve-invents-a-clean-record")

    def test_a_reader_that_accepts_an_unknown_kind_is_refused(self):
        self.assert_refused("reader-accepts-an-unknown-kind")

    def test_a_reader_that_accepts_a_short_row_is_refused(self):
        self.assert_refused("reader-accepts-a-short-row")

    def test_a_reader_that_accepts_a_foreign_field_is_refused(self):
        self.assert_refused("reader-accepts-a-foreign-field")


if __name__ == "__main__":
    unittest.main()
