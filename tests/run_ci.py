#!/usr/bin/env python3
"""Unified CI Test Runner for GoWave Auto NGINX.
Manages 5 distinct test suites (nonroot, root, integration, services, systemd),
enforces strict EUID privilege boundaries, and provides completeness validation.
"""
import argparse
import importlib
import inspect
import os
from pathlib import Path
import sys
import unittest

SUITES = {
    "nonroot": (
        "test_os_detection.TestOSDetection",
        "test_security.TestSecurityModule",
        "test_panel_deployment.TestPanelDeployment",
        "test_node_integration.TestNodeIntegration",
        "test_node_integration.TestWorkerPayloadBootstrap",
        "test_node_integration.TestLocalNodeIdempotency",
        "test_node_integration.TestPinnedNodeInstaller",
        "test_nginx_routing.TestNginxRouting",
        "test_nonroot_lint.TestNonrootLint",
        "test_backup_format_v1.TestBackupFormatV1",
        "test_user_links.TestUserLinks",
        "test_podman_address.TestPodmanAddressOverride",
        "test_podman_acme_fixture.TestPodmanAcmeFixture",
        "test_podman_fixture_isolation.TestPodmanFixtureIsolation",
        "test_podman_client_trust.TestPodmanClientTrust",
        "test_podman_target_image.TestPodmanTargetImage",
        "test_podman_client_image.TestClientImageContract",
        "test_podman_client_image.TestClientArtifactInstaller",
        "test_podman_topology.TestPodmanTopology",
        "test_podman_aio.TestAioSuite",
        "test_podman_aio.TestAioVerificationCases",
        "test_podman_aio.TestPanelApiCases",
        "test_podman_aio.TestPanelSurfaceProbe",
        "test_podman_aio.TestRestartCase",
        "test_podman_aio.TestIdempotentCase",
        "test_podman_aio.TestNegativeCases",
        "test_podman_aio.TestNginxConfigCase",
        "test_podman_subscriptions.TestPanelSubscriptionProbe",
        "test_podman_subscriptions.TestSubscriptionClientProbe",
        "test_podman_subscriptions.TestSubscriptionCases",
        "test_podman_subscriptions.TestSubscriptionTopology",
        "test_podman_subscriptions.TestSubscriptionWiring",
        "test_podman_traffic.TestTrafficProbeHelpers",
        "test_podman_traffic.TestTrafficEngine",
        "test_podman_traffic.TestTrafficProbeTransfer",
        "test_podman_traffic.TestTrafficProbeTransferOne",
        "test_podman_traffic.TestTrafficProbeDirect",
        "test_podman_traffic.TestTrafficProbeRevocation",
        "test_podman_traffic.TestTrafficProbeProhibited",
        "test_podman_traffic.TestTrafficProbeReadiness",
        "test_podman_traffic.TestDataPlaneCase",
        "test_podman_traffic.TestMatrixCase",
        "test_podman_traffic.TestRevocationCase",
        "test_podman_traffic.TestTrafficTopology",
        "test_podman_matrix.TestProtocolMatrix",
        "test_podman_matrix.TestMatrixCatalog",
        "test_podman_multi_node.TestMultiNodePlan",
        "test_podman_multi_node.TestSshHostKeyCase",
        "test_podman_multi_node.TestMultiNodeRoles",
        "test_podman_multi_node.TestWorkerTrustPin",
        "test_podman_multi_node.TestPodmanExecAttachesStdin",
        "test_podman_multi_node.TestMultiNodeZone",
        "test_podman_multi_node.TestWorkerProvisioningCommand",
        "test_podman_multi_node.TestWorkerControlReport",
        "test_podman_multi_node.TestMasterAddressCase",
        "test_podman_multi_node.TestMtlsVerifierReport",
        "test_podman_multi_node.TestMtlsNegativeReport",
        "test_podman_multi_node.TestMtlsCases",
        "test_podman_multi_node.TestMtlsProbeMemoization",
        "test_podman_multi_node.TestWorkerRegistrationCase",
        "test_podman_multi_node.TestRunnerEntrypoint",
        "test_podman_multi_node.TestMultiNodeCounts",
        "test_podman_multi_node.TestMatrixCase",
        "test_podman_multi_node.TestEgressCase",
        "test_podman_multi_node.TestDataPlaneSourceEvidence",
        "test_podman_multi_node.TestMultiNodeSuite",
        "test_podman_multi_node.TestNginxConfigCase",
        "test_podman_multi_node.TestWorkerOutageCase",
        "test_podman_multi_node.TestWorkerPeerWait",
        "test_podman_multi_node.TestWorkerRestartCase",
        "test_podman_multi_node.TestWorkerUnitControl",
        "test_podman_denial.TestDenialParsers",
        "test_podman_denial.TestDenialClassification",
        "test_podman_denial.TestManagementDenialCase",
        "test_podman_denial.TestDenialClassificationCase",
        "test_podman_denial.TestDenialFactsVantage",
        "test_podman_cluster.TestClusterScope",
        "test_podman_cluster.TestClusterCases",
        "test_podman_cluster.TestVisionCase",
        "test_podman_worker_state.TestWorkerProbeParsing",
        "test_podman_worker_state.TestWorkerProbeContract",
        "test_podman_worker_state.TestWorkerStateCase",
        "test_podman_worker_state.TestWorkerConfigCase",
        "test_podman_worker_subscriptions.TestSubscriptionDomains",
        "test_podman_worker_subscriptions.TestClusterSubscriptionInventory",
        "test_podman_worker_subscriptions.TestWorkerSubscriptionCases",
        "test_podman_worker_subscriptions.TestNodeNames",
        "test_podman_worker_subscriptions.TestMatrixExpectations",
        "test_podman_worker_subscriptions.TestWorkerDataPlaneCase",
        "test_podman_cleanup.TestPodmanStaleRunRecovery",
        "test_fixture_dns.TestDnsFixture",
        "test_fixture_echo.TestEchoFixture",
        "test_fixture_echo.TestEchoFixtureSourceAllowlist",
        "test_podman_images.TestPodmanImagePinning",
        "test_podman_images.TestPodmanEnvironmentFingerprint",
        "test_podman_preconditions.TestPodmanPrivilegeScopes",
        "test_podman_readiness.TestNoUnboundedWaits",
        "test_podman_readiness.TestWaitUntil",
        "test_podman_readiness.TestBoundedReadinessHelpers",
        "test_podman_runner.TestPodmanRunnerContract",
        "test_podman_runner.TestPodmanRunOwnership",
        "test_podman_runner.TestArtifactOwnership",
    ),
    "integration": (
        "test_api_client.TestAPIClient",
        "test_api_client.TestRepeatedInstallContract",
        "test_integration.TestIntegration",
    ),
    "services": (
        "test_services.TestServices",
    ),
    "root": (
        "test_root.TestRoot",
    ),
    "systemd": (
        "test_systemd_runner.TestSystemdRunner",
    ),
}


def collect():
    directory = Path(__file__).resolve().parent
    sys.path.insert(0, str(directory))
    modules = sorted(directory.glob("test_*.py"))
    classes = {}

    for path in modules:
        module = importlib.import_module(path.stem)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, unittest.TestCase) and cls.__module__ == module.__name__:
                classes[f"{module.__name__}.{cls.__qualname__}"] = cls

    assignments = {}
    for suite, names in SUITES.items():
        for name in names:
            if name in assignments:
                raise ValueError(f"Duplicate suite assignment: {name}")
            assignments[name] = suite

    unassigned = sorted(classes.keys() - assignments.keys())
    stale = sorted(assignments.keys() - classes.keys())
    if unassigned or stale:
        raise ValueError(f"Unassigned TestCase classes: {unassigned}; stale registry entries: {stale}")

    loader = unittest.TestLoader()
    suites = {name: [] for name in SUITES}
    test_ids = set()

    for name, cls in sorted(classes.items()):
        if not loader.getTestCaseNames(cls):
            raise ValueError(f"TestCase has no test methods: {name}")
        tests = list(loader.loadTestsFromTestCase(cls))
        for test in tests:
            if test.id() in test_ids:
                raise ValueError(f"Duplicate test ID: {test.id()}")
            test_ids.add(test.id())
        suites[assignments[name]].extend(tests)

    if loader.errors:
        raise ValueError("Test collection errors: " + "\n".join(loader.errors))

    for name, tests in suites.items():
        if not tests:
            raise ValueError(f"Empty suite: {name}")

    print("CI TEST INVENTORY")
    print(f"Modules:          {len(modules)}")
    print(f"TestCase classes: {len(classes)}")
    print(f"Unique tests:     {len(test_ids)}")
    for name, tests in suites.items():
        print(f"{name:15}: {len(tests)}")
    print("COMPLETENESS: PASS", flush=True)
    return suites


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-completeness", action="store_true", help="Validate test class registry completeness")
    mode.add_argument("--suite", choices=SUITES.keys(), help="Target test suite to execute")
    args = parser.parse_args()

    # Enforce EUID privilege separation:
    # nonroot, integration, services require os.geteuid() != 0
    # root, systemd require os.geteuid() == 0
    if args.suite and ((args.suite in ("root", "systemd")) != (os.geteuid() == 0)):
        required_euid = "EUID 0" if args.suite in ("root", "systemd") else "EUID != 0"
        print(f"PRIVILEGE: FAIL — {args.suite} requires {required_euid}", file=sys.stderr)
        return 1

    try:
        suites = collect()
    except (Exception, SystemExit) as error:
        print(f"COMPLETENESS: FAIL — {error}", file=sys.stderr)
        return 1

    if args.check_completeness:
        return 0

    suite_to_run = unittest.TestSuite(suites[args.suite])
    result = unittest.TextTestRunner(verbosity=2).run(suite_to_run)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
