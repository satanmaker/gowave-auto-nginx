# Design

## Context

The interactive loop clears the screen on each call to `main_menu`. `cmd_install` emits its completion banner before `wizard_onboard_nodes`, which captures both output streams per worker. `wizard_register_host` checks a collected tuple, not the field currently being entered. Single add supplies a name and IP to SSH bootstrap, whereas batch add falls back to the domain. `host_projection` generates protocol remarks and `provision_hosts` also uses the mutable remark as a lookup key. The new labels are therefore a migration concern, not just a translation.

## Goals / Non-Goals

Keep navigation line-oriented and usable over SSH; share the same validation and outcome rules across entrypoints. Do not change positional syntax, upstream binaries, Xray routing or the credential lifecycle. No full-screen TUI, background GeoIP daemon, estimated progress percentages, automatic client failover or retroactive global rename.

## Decisions

1. **One route, role-specific cards.** Language → menu → explicit topology → Panel → local node if present → numbered remote node cards → review → apply → result → menu. Existing Panel → verify identity/inventory → remote card → review → apply → result. Status → report → Enter → menu. Example review actions: `Начать установку`, `Изменить настройки панели`, `Изменить узел`, `Отменить и вернуться`. Make progress and prompts RU/EN catalog entries rather than translating raw process output. Update the variant table in `docs/SETUP_WIZARD.md`, which currently endorses the mixed topology for production.
2. **Separate names, addressing and identity.** Keep display name separate from primary/cover/Vision DNS values and SSH target; retain existing safe identifier restrictions wherever a name reaches tags, paths or CLI. Validate at field entry against prior cards and current siblings; exclude only the edited field itself. Compare trimmed names consistently against the Panel and plan (treat case-only differences as collisions in the wizard). Check again under the registration lock; a collision is not permission to adopt/update the existing node. Reconcile the same managed UUID on retry, not an arbitrary equal name. Use the accepted local name throughout provisioning instead of a hidden `local-node` default on wizard runs.
3. **Interactive results are data, not raw logs.** Preserve native failure codes and rollback/ERR handling inside operations; isolate the operation boundary from menu navigation rather than disabling errexit across nested installer functions. Send allowlisted stage events to the interactive terminal independently of captured diagnostics. Keep full host-key confirmation and hidden password input. Read back the expected node UUID/association from the verified Panel before claiming registration; report indeterminate verification as such. Keep Panel success separate even if every remote node fails. Existing partial-state inspection precedes selective retry.
4. **Country after access, before publishing labels.** On a traffic node only, use a bounded HTTPS country lookup from that node's outbound route (no management proxy or Panel fallback). Send no name, domain or credentials; the service necessarily sees the source IP. Use one timeout-bounded attempt and validate against assigned country codes. A localizable country name and flag accompany the suggestion; Enter accepts, `de` overrides to DE, invalid input stays on the field. With no valid suggestion require manual input in the wizard. Review marks pending countries rather than opening SSH before consent. Persist the confirmed code alongside managed node identity for update/retry; no lookup or new prompt in unattended legacy runs.
5. **Presentation is not identity.** Render `🇳🇱 VLESS · REALITY · Vision — ams-01`, `🇳🇱 VLESS · TLS · Vision — ams-01`, `🇳🇱 VLESS · XHTTP · TLS — ams-01`, `🇳🇱 VLESS · WebSocket · TLS — ams-01`, `🇳🇱 Trojan · gRPC · TLS — ams-01` for the enabled profiles. Disable only the optional TLS Vision entry when unavailable. Preserve protocol settings and machine identifiers. Match managed Hosts by recorded UUID, or unique proven node/inbound ownership for legacy records. Never match by label alone. Preserve exact names across emitted JSON/YAML and group references.

## Risks / Trade-offs

- GeoIP may describe NAT rather than a custom traffic route → treat the result as a suggestion, preserve manual correction, permit deployment during a provider outage.
- Failure after registration or during temporary-access cleanup → show what was verified and the failed phase, not unconditional success; do not retry a possibly existing node blindly.
- Old tests, consumers and client selections may key on the old label → migrate Hosts in place, test group references and document that clients may need to reselect after refresh.

## Migration Plan

Ship UUID/ownership-aware reconciliation before emitting new labels. Leave existing unconfirmed deployments untouched; on managed reconciliation with confirmed metadata patch identified Hosts rather than creating replacements. If ownership is ambiguous, report a conflict and leave records untouched. Preserve prior remarks/UUIDs through existing transaction recovery. For downgrade, restore prior remarks for affected managed UUIDs before using an older remark-keyed provisioner; do not delete and recreate Hosts.
