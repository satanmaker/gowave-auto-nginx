# Proposal

## Why

Operators lose status and completion messages when the menu redraws, lose a whole plan to a single conflicting domain, and cannot tell whether remote work has finished or is waiting for input. Subscription labels do not identify the exit country and the wizard offers no consistent way to name nodes.

## What Changes

- Describe where the Panel and each traffic node run, explain failure isolation, and distinguish new deployment from adding a server to an existing Panel.
- Collect role-specific fields with inline correction; offer editable, unique node names in all topologies and a review before mutation.
- Keep status and final outcomes readable until an explicit return; show safe per-node progress, verified results and selective retry, including single-node additions.
- Detect exit country from each node, let the operator correct it, and update managed subscription labels in place on reconciliation.
- Keep positional operations prompt-free. No upstream binary changes, new terminal UI dependency, failover feature or fleet-wide relabelling job.

## Capabilities

### New Capabilities
- `subscription-labels`: exit-country selection and readable, stable managed profile presentation across subscription formats.

### Modified Capabilities
- `setup-wizard`: topology guidance, contextual inputs, recoverable validation and naming.
- `interactive-deployment`: readable status, plan review, phase visibility and durable operation results.

## Impact

Touches the interactive shell, RU/EN catalog, SSH onboarding, local and remote provisioning, Panel Host reconciliation, operator guide and acceptance tests. The visible profile names change for managed nodes with confirmed metadata; transports, credentials, subscription URLs and upstream API contracts do not.
