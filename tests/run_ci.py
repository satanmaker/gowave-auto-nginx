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
        "test_preflight.TestPreflightInputs",
        "test_preflight.TestNodeEnvironmentContract",
        "test_preflight.TestWorkerPayloadContract",
        "test_preflight.TestPreflightProxyRefusal",
        "test_preflight.TestPreflightDocumentation",
        "test_failure_report.TestFailureReport",
        "test_security.TestSecurityModule",
        "test_panel_deployment.TestPanelDeployment",
        "test_artifact_fetch.TestVerifiedArtifactFetch",
        "test_artifact_fetch.TestPinnedInstallerHosts",
        "test_artifact_fetch.TestPanelAssetVerification",
        "test_node_integration.TestNodeIntegration",
        "test_node_integration.TestWorkerPayloadBootstrap",
        "test_node_integration.TestLocalNodeIdempotency",
        "test_node_integration.TestPinnedNodeInstaller",
        "test_node_integration.TestPinnedXrayCore",
        "test_node_integration.TestNodeInstallerRetry",
        "test_node_integration.TestWorkerInstallerRetry",
        "test_node_integration.TestWorkerReapply",
        "test_node_integration.TestWorkerDeployHookOwnership",
        "test_nginx_routing.TestNginxRouting",
        "test_install_mode.TestInstallArgumentContract",
        "test_install_mode.TestPanelOnlyNginxRendering",
        "test_install_mode.TestInstallSourceContract",
        "test_install_mode.TestInstallProvisioning",
        "test_install_mode.TestNodeSquadProvisioning",
        "test_install_mode.TestSquadReuse",
        "test_install_mode.TestPanelOnlyHealthAndStatus",
        "test_wizard.TestWizardCatalog",
        "test_wizard.TestVariantMenu",
        "test_wizard.TestHostnameValidation",
        "test_wizard.TestPlanRegistration",
        "test_wizard.TestCollectPlan",
        "test_wizard.TestCertificateBudget",
        "test_wizard.TestCertificatePreflight",
        "test_wizard.TestWizardEntry",
        "test_wizard.TestInteractiveMenu",
        "test_wizard.TestPlanReview",
        "test_wizard.TestLocalNodeName",
        "test_wizard.TestWizardDocumentation",
        "test_wizard.TestSSHReachability",
        "test_wizard.TestOnboardingOutcomes",
        "test_wizard.TestPanelApiVerification",
        "test_wizard.TestPanelWorkerName",
        "test_wizard.TestPanelInventoryRead",
        "test_ssh_bootstrap.TestFingerprintConfirmation",
        "test_ssh_bootstrap.TestHostKeyScan",
        "test_ssh_bootstrap.TestBootstrapPayloads",
        "test_ssh_bootstrap.TestPasswordHandling",
        "test_ssh_bootstrap.TestTimerGate",
        "test_ssh_bootstrap.TestOnboardingLifecycle",
        "test_ssh_bootstrap.TestPromptStreams",
        "test_ssh_bootstrap.TestStageNotices",
        "test_nonroot_lint.TestNonrootLint",
        "test_nonroot_lint.TestShellFailurePaths",
        "test_backup_format_v1.TestBackupFormatV1",
        "test_backup_format_v1.TestIncompleteArchiveRejection",
        "test_user_links.TestUserLinks",
        "test_podman_address.TestPodmanAddressOverride",
        "test_podman_acme_fixture.TestPodmanAcmeFixture",
        "test_podman_fixture_isolation.TestPodmanFixtureIsolation",
        "test_podman_client_trust.TestPodmanClientTrust",
        "test_podman_target_image.TestPodmanTargetImage",
        "test_podman_client_image.TestClientImageContract",
        "test_podman_client_image.TestClientArtifactInstaller",
        "test_podman_topology.TestPodmanTopology",
        "test_podman_topology.TestPanelOnlyTopology",
        "test_podman_argv_observer.TestStraceParsing",
        "test_podman_argv_observer.TestAcceptanceFixtures",
        "test_podman_argv_observer.TestObserverWiring",
        "test_podman_argv_observer.TestNodeAddIsTraced",
        "test_podman_argv_observer.TestArgvObserverCase",
        "test_podman_argv_observer.TestObserverDocumentation",
        "test_podman_aio.TestAioSuite",
        "test_podman_aio.TestHostsBlock",
        "test_podman_aio.TestAioVerificationCases",
        "test_podman_aio.TestPanelApiCases",
        "test_podman_aio.TestPanelSurfaceProbe",
        "test_podman_aio.TestPanelAuthNegativeCase",
        "test_podman_aio.TestPanelAuthNegativeProbe",
        "test_podman_aio.TestPanelApiClientCase",
        "test_podman_aio.TestPanelApiClientProbe",
        "test_podman_aio.TestPanelEnvValue",
        "test_podman_aio.TestRestartCase",
        "test_podman_aio.TestIdempotentCase",
        "test_podman_aio.TestNegativeCases",
        "test_podman_aio.TestVisionFailureCase",
        "test_podman_aio.TestFaultCases",
        "test_podman_aio.TestBackupStoreFullCase",
        "test_podman_aio.TestNginxConfigCase",
        "test_podman_aio.TestRestoreDeadlineCase",
        "test_podman_aio.TestInstalledVersionCases",
        "test_podman_aio.TestTlsSurfaceCase",
        "test_podman_aio.TestTlsCaBundleCase",
        "test_podman_aio.TestDecoyCase",
        "test_podman_aio.TestHygieneCase",
        "test_podman_aio.TestVhostHygieneProbe",
        "test_podman_aio.TestPreflightInputCase",
        "test_podman_aio.TestVisionRouteCase",
        "test_podman_aio.TestTlsPolicyParse",
        "test_podman_aio.TestAcmeRenewalCase",
        "test_podman_aio.TestAcmeRenewalProbe",
        "test_podman_aio.TestAcmeOutageCase",
        "test_podman_aio.TestAcmeOutageProbe",
        "test_podman_aio.TestChannelCases",
        "test_podman_aio.TestPacketEvidenceCase",
        "test_podman_aio.TestRedactedCredentialsCase",
        "test_podman_aio.TestDiagnosticArtifactsCase",
        "test_podman_aio.TestRevocationTransferRetry",
        "test_podman_dns.TestDnsProbe",
        "test_podman_dns.TestDnsZoneStore",
        "test_podman_dns.TestDnsCase",
        "test_podman_dns.TestDnsCaseWiring",
        "test_podman_subscriptions.TestPanelSubscriptionProbe",
        "test_podman_subscriptions.TestChannelClientSurface",
        "test_podman_subscriptions.TestSubscriptionClientProbe",
        "test_podman_subscriptions.TestSubscriptionCases",
        "test_podman_subscriptions.TestSubscriptionEdgeCases",
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
        "test_podman_traffic.TestMihomoLaunch",
        "test_podman_traffic.TestDataPlaneCase",
        "test_podman_traffic.TestMatrixCase",
        "test_podman_traffic.TestRevocationCase",
        "test_podman_traffic.TestTrafficTopology",
        "test_podman_ingress.TestListenerPort",
        "test_podman_ingress.TestProbePersistsNothing",
        "test_podman_ingress.TestMeasure",
        "test_podman_ingress.TestEvaluate",
        "test_podman_ingress.TestEvidenceAndRequire",
        "test_podman_matrix.TestProtocolMatrix",
        "test_podman_matrix.TestMatrixCatalog",
        "test_podman_matrix.TestHostProjection",
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
        "test_podman_multi_node.TestTlsSurfaceCase",
        "test_podman_multi_node.TestCoverDeriveCase",
        "test_podman_multi_node.TestCoverSiteCase",
        "test_podman_multi_node.TestDecoyRouteCase",
        "test_podman_multi_node.TestVisionRouteCase",
        "test_podman_multi_node.TestAcme80Case",
        "test_podman_multi_node.TestCoverUnresolvedCase",
        "test_podman_multi_node.TestBackupProbeScript",
        "test_podman_multi_node.TestBackupCase",
        "test_podman_multi_node.TestBackupArchiveParsing",
        "test_podman_multi_node.TestBackupVolumeProbe",
        "test_podman_multi_node.TestArtifactLeaks",
        "test_podman_multi_node.TestBackupVolumeCase",
        "test_podman_multi_node.TestBackupRejectCase",
        "test_podman_multi_node.TestRestoreScope",
        "test_podman_multi_node.TestRestoreCase",
        "test_podman_multi_node.TestNodeEnvProbe",
        "test_podman_multi_node.TestWorkerOutageCase",
        "test_podman_multi_node.TestWorkerPeerWait",
        "test_podman_multi_node.TestWorkerRestartCase",
        "test_podman_multi_node.TestSshServiceDownCase",
        "test_podman_multi_node.TestWorkerUnitControl",
        "test_podman_multi_node.TestMasterAccessCase",
        "test_podman_multi_node.TestDuplicateAddCase",
        "test_podman_multi_node.TestIpv6PolicyCase",
        "test_podman_multi_node.TestPacketWrongHostCase",
        "test_podman_multi_node.TestVisionCompensationCase",
        "test_podman_multi_node.TestAddNodeRefusedCase",
        "test_podman_multi_node.TestPartialSuccessCase",
        "test_podman_multi_node.TestEnvContractCase",
        "test_podman_panel_only.TestPanelOnlySuite",
        "test_podman_panel_only.TestPanelOnlyInstallCase",
        "test_podman_panel_only.TestPanelOnlyHostCase",
        "test_podman_panel_only.TestPanelOnlyApiCase",
        "test_podman_panel_only.TestPanelOnlySquadCase",
        "test_podman_panel_only.TestPanelOnlyRefusalProbe",
        "test_podman_panel_only.TestPanelOnlyAddNodeRefusedCase",
        "test_podman_denial.TestDenialParsers",
        "test_podman_denial.TestDenialClassification",
        "test_podman_denial.TestManagementDenialCase",
        "test_podman_denial.TestDenialClassificationCase",
        "test_podman_denial.TestDenialFactsVantage",
        "test_podman_denial.TestHostFirewallParsers",
        "test_podman_denial.TestHostFirewallIpv6Parsers",
        "test_podman_cluster.TestClusterScope",
        "test_podman_cluster.TestClusterCases",
        "test_podman_cluster.TestVisionCase",
        "test_podman_worker_state.TestWorkerProbeParsing",
        "test_podman_worker_state.TestWorkerProbeContract",
        "test_podman_worker_state.TestWorkerStateCase",
        "test_podman_worker_state.TestWorkerConfigCase",
        "test_podman_worker_state.TestWorkerCoreVersion",
        "test_podman_worker_subscriptions.TestSubscriptionDomains",
        "test_podman_worker_subscriptions.TestClusterSubscriptionInventory",
        "test_podman_worker_subscriptions.TestWorkerSubscriptionCases",
        "test_podman_worker_subscriptions.TestNodeNames",
        "test_podman_worker_subscriptions.TestMatrixExpectations",
        "test_podman_worker_subscriptions.TestWorkerDataPlaneCase",
        "test_podman_cleanup.TestPodmanStaleRunRecovery",
        "test_podman_cleanup.TestEntrypointReclaimsStaleRuns",
        "test_podman_docs.TestDiscoveryInventory",
        "test_podman_docs.TestPanelApiContract",
        "test_podman_docs.TestSubscriptionFamilyInventory",
        "test_podman_docs.TestJsonShapeContract",
        "test_podman_docs.TestLiveContractReconciliation",
        "test_podman_docs.TestLiveContractParity",
        "test_podman_docs.TestOsMatrixReconciliation",
        "test_podman_docs.TestReusableFixtureInventory",
        "test_podman_docs.TestContourBoundary",
        "test_podman_docs.TestPodmanE2EDocumentation",
        "test_podman_docs.TestResultStatusContract",
        "test_podman_docs.TestTeardownPolicyContract",
        "test_podman_docs.TestVisionContract",
        "test_fixture_dns.TestDnsFixture",
        "test_fixture_echo.TestEchoFixture",
        "test_fixture_echo.TestEchoFixtureSourceAllowlist",
        "test_ci_isolation.TestNormalCiIsolation",
        "test_podman_images.TestPodmanImagePinning",
        "test_podman_images.TestPodmanEnvironmentFingerprint",
        "test_podman_preconditions.TestPodmanPrivilegeScopes",
        "test_podman_readiness.TestNoUnboundedWaits",
        "test_podman_readiness.TestWaitUntil",
        "test_podman_readiness.TestBoundedReadinessHelpers",
        "test_podman_runner.TestPodmanRunnerContract",
        "test_podman_runner.TestResultSemantics",
        "test_podman_runner.TestHarnessLimitVerdict",
        "test_podman_runner.TestPodmanRunOwnership",
        "test_podman_runner.TestArtifactOwnership",
        "test_podman_runner.TestFailureDiagnosticsHook",
        "test_podman_runner.TestPodmanDiagnosticsBundle",
        "test_podman_runner.TestPodmanContainerDiscovery",
        "test_podman_groups.TestGroupDefinitions",
        "test_podman_groups.TestUnmet",
        "test_podman_groups.TestRequiredGroupRun",
        "test_podman_gate.TestPodmanGateContract",
        "test_podman_pre_push.TestPrePushGate",
        "test_podman_gate_tiers.TestGateTiers",
        "test_podman_acme_mode.TestAcmeMode",
        "test_podman_tls_anchors.TestTlsAnchors",
        "test_podman_budget.TestDeclaredBudget",
        "test_podman_budget.TestBudgetCase",
        "test_podman_budget.TestEntrypointBudget",
        "test_podman_budget.TestOperationCeilings",
        "test_podman_status.TestStatusCase",
        "test_podman_teardown.TestTeardownCase",
        "test_podman_preflight_cases.TestPreflightRegistration",
        "test_podman_preflight_cases.TestPreflightLocalCases",
        "test_podman_preflight_cases.TestPreflightDnsCases",
        "test_podman_negative_matrix.TestNegativeMatrixRegistration",
        "test_podman_negative_matrix.TestNegativeMatrixCases",
        "test_podman_negative_matrix.TestNegativeMatrixDamage",
        "test_podman_lock_cases.TestLockHolderProgram",
        "test_podman_lock_cases.TestPairLockOverLocalHolders",
        "test_podman_lock_cases.TestLeaseContract",
        "test_podman_lock_cases.TestRunStateGate",
        "test_podman_lock_cases.TestLockDrivers",
        "test_podman_lock_cases.TestCaseGuards",
        "test_podman_lock_cases.TestOwnershipShapeCapability",
        "test_podman_lock_cases.TestWorkerLeasePlumbing",
        "test_podman_lock_cases.TestCliEntryPointTable",
        "test_podman_lock_cases.TestCliCommandConstruction",
        "test_podman_lock_cases.TestLockRegistration",
        "test_podman_runstate_cases.TestRunStateCases",
        "test_podman_runstate_cases.TestRunStateRegistration",
        "test_podman_environment_gate.TestEnvironmentGateRegistration",
        "test_podman_environment_gate.TestGateHostBootstrap",
        "test_podman_environment_gate.TestEnvironmentGateCases",
        "test_podman_environment_gate.TestEnvironmentGateDamage",
        "test_podman_trust_bundle.TestTrustBundleRegistration",
        "test_podman_trust_bundle.TestProductionBundleCase",
        "test_podman_trust_bundle.TestTrustBundleDamage",
        "test_podman_staging_trust.TestStagingTrustRegistration",
        "test_podman_staging_trust.TestStagingTrustCases",
        "test_podman_staging_trust.TestStagingTrustDamage",
        "test_podman_skip_policy.TestSkipPolicyRegistration",
        "test_podman_skip_policy.TestSkippedTrafficCase",
        "test_podman_skip_policy.TestSkipPolicyDamage",
        "test_podman_local_ci.TestLocalCiRegistration",
        "test_podman_local_ci.TestLocalCiCase",
        "test_podman_local_ci.TestLocalCiDamage",
        "test_podman_operator_access.TestOperatorAccessRegistration",
        "test_podman_operator_access.TestOperatorAccessCases",
        "test_podman_operator_access.TestOperatorAccessDamage",
        "test_podman_hook_ownership.TestHookOwnershipRegistration",
        "test_podman_hook_ownership.TestHookOwnershipCase",
        "test_podman_hook_ownership.TestHookOwnershipDamage",
        "test_podman_hook_ownership.TestHookShapeCase",
        "test_podman_hook_ownership.TestHookShapeDamage",
        "test_podman_ownership.TestOwnershipRegistration",
        "test_podman_ownership.TestOwnershipCase",
        "test_podman_ownership.TestOwnershipDamage",
        "test_podman_ownership_targets.TestOwnershipTargetsRegistration",
        "test_podman_ownership_targets.TestOwnershipTargetsCase",
        "test_podman_ownership_targets.TestOwnershipTargetsDamage",
        "test_podman_firewall_image.TestFirewallImageRegistration",
        "test_podman_firewall_image.TestFirewallImageCase",
        "test_podman_firewall_image.TestFirewallImageDamage",
        "test_podman_firewall_image.TestFirewallImageTraceability",
        "test_podman_mutation_baseline.TestMutationBaselineRegistration",
        "test_podman_mutation_baseline.TestMutationBaselineCase",
        "test_podman_mutation_baseline.TestMutationBaselineDamage",
        "test_podman_worker_journal.TestWorkerJournalRegistration",
        "test_podman_worker_journal.TestWorkerJournalCase",
        "test_podman_worker_journal.TestWorkerJournalDamage",
        "test_podman_package_residual.TestPackageResidualRegistration",
        "test_podman_package_residual.TestPackageResidualCase",
        "test_podman_package_residual.TestPackageResidualDamage",
        "test_podman_signal_compensation.TestSignalCompensationRegistration",
        "test_podman_signal_compensation.TestSignalCompensationCase",
        "test_podman_signal_compensation.TestSignalCompensationDamage",
        "test_podman_transaction_recovery.TestTransactionRecoveryRegistration",
        "test_podman_transaction_recovery.TestTransactionRecoveryCase",
        "test_podman_transaction_recovery.TestTransactionRecoveryDamage",
        "test_podman_rollback_sides.TestRollbackSidesRegistration",
        "test_podman_rollback_sides.TestRollbackSidesCase",
        "test_podman_rollback_sides.TestRollbackSideRecord",
        "test_podman_rollback_sides.TestRollbackSidesDamage",
        "test_podman_negative_journal.TestNegativeJournalRegistration",
        "test_podman_negative_journal.TestNegativeJournalScript",
        "test_podman_negative_journal.TestNegativeJournalCase",
        "test_podman_negative_journal.TestNegativeJournalDamage",
        "test_podman_revocation.TestRevocationRegistration",
        "test_podman_revocation.TestRevocationCase",
        "test_podman_revocation.TestRevocationDamage",
        "test_podman_vision.TestVisionConfigCase",
        "test_podman_vision.TestVisionGateCase",
        "test_podman_vision.TestEndpointContract",
        "test_podman_catalog.TestImplementationRegistry",
        "test_podman_catalog.TestDivergenceGuard",
        "test_podman_catalog.TestEntrypointRefusesAnUnknownSuite",
        "test_podman_catalog.TestJustifiedExclusions",
        "test_podman_catalog.TestParityInventory",
        "test_podman_catalog.TestPodmanFirstPromotion",
        "test_podman_catalog.TestPromotionPath",
        "test_podman_catalog.TestRunStarts",
        "test_podman_catalog.TestScenarioClassification",
        "test_podman_behaviors.TestBehaviorInventory",
        "test_podman_contracts.TestSharedContracts",
        "test_ci_workflows.TestIndependentAcceptanceWorkflows",
        "test_podman_redaction.TestRedactionFilter",
        "test_podman_redaction.TestArtifactTreeHoldsNoSentinel",
        "test_podman_redaction.TestDiagnosticsNeverPrintValues",
        "test_podman_traceability.TestTraceabilityRules",
        "test_podman_traceability.TestNamedBehaviours",
    ),
    "integration": (
        "test_api_client.TestAPIClient",
        "test_api_client.TestAttachSquadToUser",
        "test_api_client.TestRepeatedInstallContract",
        "test_integration.TestIntegration",
    ),
    "services": (
        "test_services.TestServices",
    ),
    "root": (
        "test_root.TestRoot",
        "test_root.TestChannelSwitchRollback",
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
