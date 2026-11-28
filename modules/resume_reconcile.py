#!/usr/bin/env python3
"""Classify a recorded resume expectation against the Panel's live answer.

A checkpoint records a verdict about a moment. A resume may not replay the
verdict: it reads what the Panel answers now and compares it with what the
draft recorded. This module is that comparison, and it is the only place that
decides whether a recorded component is still the component the draft named.

One call takes two documents and answers with one of six classes:

    match         the live answer is the recorded one; keep the checkpoint
    missing       the recorded resource is gone and nothing else claims it;
                  the component is re-created
    drift         the recorded identity is proven but its profile, inbound set,
                  Host records or host security identity differ; the component
                  is re-applied
    incompatible  a schema or installer revision this installer cannot serve;
                  the component stops
    ambiguous     legacy or conflicting state that cannot be attributed to the
                  recorded identity; the component stops
    unreachable   the Panel (or the host that holds the security identity) did
                  not answer; nothing is changed and the draft stays resumable

`missing` and `drift` name only work that can be rebuilt without guessing an
identity. A Host record holding a recorded domain under another UUID, a node
whose name is held by a different UUID, a profile or inbound that no longer
exists and a security report from another machine are all `ambiguous`: the
resume stops that component instead of adopting a stranger's resource or
registering a second node under a new identity.

Input document (standard input, one JSON object):

    {
      "expectation": {
        "component": "node-1",              # identity in the draft
        "kind": "node",                     # "panel", "local-node" or "node"
        "recorded": {                       # what the checkpoint recorded
          "state": "verified", "stage": "complete", "attempt": 1,
          "node_uuid": "...", "profile_uuid": "...",
          "inbound_uuids": ["..."], "host_uuids": ["..."],
          "node_name": "ams-01", "host_domains": ["panel.example.com"],
          "schema_version": 2,              # optional
          "installer_revision": "abc1234"
        }
      },
      "live": {                             # what the Panel answered
        "reachable": true,
        "schema_version": 2,                # state.json schemaVersion
        "installer_revision": "abc1234",    # this run's revision, optional
        "nodes": [...], "hosts": [...],
        "profiles": [{"uuid": "...", "inbounds": ["..."]}]
      },
      "security": {                         # host readiness, optional
        "recorded": {...security report...},
        "live": {...security report...},
        "error": "unreachable"              # when the host could not be read
      }
    }

Output (standard output, one JSON object):

    {"component": "node-1", "class": "drift", "action": "reapply",
     "reason": "profile_association_changed", "detail": "...",
     "node_uuid": "..."}

Modes:

    --probe        read the Panel and print the live document
    --classify     classify the document on standard input

`--probe` needs `--credentials` and reads `--state` for the schema version. It
prints `{"reachable": false, "error": "..."}` when the Panel cannot be read,
which the classifier reports as `unreachable` rather than as a missing
component: an unread Panel disproves nothing.
"""
import argparse
import json
import sys
from dataclasses import dataclass

from modules.api_client import GoWaveAPIError, host_ownership, resume_live_inventory
from modules.security_report import StateError, readiness

# The state.json schema this installer writes and can resume. A live Panel
# state under another schema is not something this run may rewrite.
SUPPORTED_STATE_SCHEMA = 2
# The security report schema `modules.security_report` validates.
SUPPORTED_SECURITY_SCHEMA = 1

MATCH = 'match'
MISSING = 'missing'
DRIFT = 'drift'
INCOMPATIBLE = 'incompatible'
AMBIGUOUS = 'ambiguous'
UNREACHABLE = 'unreachable'

CLASSES = (MATCH, MISSING, DRIFT, INCOMPATIBLE, AMBIGUOUS, UNREACHABLE)
ACTIONS = {
    MATCH: 'keep',
    MISSING: 'recreate',
    DRIFT: 'reapply',
    INCOMPATIBLE: 'stop',
    AMBIGUOUS: 'stop',
    UNREACHABLE: 'retry',
}


@dataclass(frozen=True)
class Verdict:
    component: str
    status: str
    reason: str
    detail: str
    node_uuid: str = ''

    @property
    def action(self):
        return ACTIONS[self.status]

    def as_dict(self):
        return {
            'component': self.component,
            'class': self.status,
            'action': self.action,
            'reason': self.reason,
            'detail': self.detail,
            'node_uuid': self.node_uuid,
        }


def _text(value):
    return value.strip() if isinstance(value, str) else ''


def _ids(value):
    """A list of non-empty identifiers, or ``None`` when the field is absent."""
    if not isinstance(value, list):
        return None
    return sorted({item for item in (str(entry) for entry in value) if item})


def _inbound_ids(items):
    if not isinstance(items, list):
        return []
    identifiers = []
    for item in items:
        if isinstance(item, dict):
            identifiers.append(str(item.get('uuid') or ''))
        else:
            identifiers.append(str(item or ''))
    return sorted({identifier for identifier in identifiers if identifier})


def _revisions_compatible(left, right):
    """Short and full Git revisions of one commit agree with each other."""
    left, right = _text(left), _text(right)
    if not left or not right or left == right:
        return True
    return left.startswith(right) or right.startswith(left)


def _verdict(component, status, reason, detail, node_uuid=''):
    return Verdict(component, status, reason, detail, node_uuid)


def _compatibility(component, recorded, live):
    """The Panel's own state schema and the installer revision that wrote it.

    Only keys the live answer carries are compared: a probe that did not read
    the host state says nothing about it, while a key present with ``None`` is
    an answer — the state names no version, and that legacy record cannot be
    attributed to what this installer serves.
    """
    if 'schema_version' in live:
        schema = live.get('schema_version')
        if schema is None:
            return _verdict(
                component, AMBIGUOUS, 'state_schema_unrecorded',
                'the live Panel state names no schema version, so this installer cannot prove '
                'it serves that state. Inspect /var/lib/gowave-auto-nginx/state.json and restore '
                'it from a backup made by this installer before resuming.')
        if type(schema) is not int:
            return _verdict(
                component, AMBIGUOUS, 'state_schema_malformed',
                f'the live Panel state reports a schema value {schema!r} that is not a version '
                'number. Repair state.json before resuming.')
        if schema != SUPPORTED_STATE_SCHEMA:
            return _verdict(
                component, INCOMPATIBLE, 'state_schema_unsupported',
                f'the live Panel state is schema {schema}; this installer serves schema '
                f'{SUPPORTED_STATE_SCHEMA}. Install the release that wrote this state, or '
                'restore the pre-update backup, before resuming.')
        recorded_schema = recorded.get('schema_version')
        if recorded_schema is not None and recorded_schema != schema:
            return _verdict(
                component, INCOMPATIBLE, 'state_schema_changed',
                f'the checkpoint recorded schema {recorded_schema} but the Panel now answers '
                f'schema {schema}. Restore the matching state before resuming.')
    if 'installer_revision' in live:
        recorded_revision = _text(recorded.get('installer_revision'))
        live_revision = _text(live.get('installer_revision'))
        if recorded_revision and not live_revision:
            return _verdict(
                component, AMBIGUOUS, 'installer_revision_unrecorded',
                f'the checkpoint was written by installer {recorded_revision} and the live state '
                'names no installer revision, so this run cannot prove the two understand the '
                'same records. Resume with the installer release that wrote this state.')
        if recorded_revision and live_revision and not _revisions_compatible(recorded_revision, live_revision):
            return _verdict(
                component, INCOMPATIBLE, 'installer_revision_changed',
                f'the checkpoint was written by installer {recorded_revision}; this run is '
                f'{live_revision}. Resume with {recorded_revision}, or start a new plan after '
                'the Panel has been verified by the running installer.')
    return None


def _domain_holder(hosts, domains, claimed):
    """The Host record that names a recorded domain without being the recorded one."""
    for host in hosts:
        if not isinstance(host, dict):
            continue
        if str(host.get('uuid') or '') in claimed:
            continue
        names = {_text(host.get('address')), _text(host.get('sni'))}
        if names & set(domains):
            # With or without a pairing, this record is a Host this run did not
            # create; rewriting it would either adopt a stranger's record or
            # leave two records for one domain.
            return host
    return None


def _node(component, recorded, live):
    """The recorded node UUID, profile, inbound set and Host records."""
    node_uuid = _text(recorded.get('node_uuid'))
    if not node_uuid:
        return _verdict(
            component, AMBIGUOUS, 'node_identity_unrecorded',
            'the checkpoint names no node UUID, so the registration cannot be attributed to '
            'the node this plan created. Inspect the Panel node list and re-register the node '
            'with an explicit UUID before resuming.')

    nodes = [node for node in live.get('nodes') or [] if isinstance(node, dict)]
    matching = [node for node in nodes if _text(node.get('uuid')) == node_uuid]
    if len(matching) > 1:
        return _verdict(
            component, AMBIGUOUS, 'node_uuid_duplicated',
            f'the Panel answered {len(matching)} nodes with UUID {node_uuid}. Resolve the '
            'duplicate registrations on the Panel before resuming.', node_uuid)
    hosts = [host for host in live.get('hosts') or [] if isinstance(host, dict)]
    profiles = [profile for profile in live.get('profiles') or [] if isinstance(profile, dict)]
    recorded_hosts = _ids(recorded.get('host_uuids'))
    host_domains = _ids(recorded.get('host_domains')) or []
    node_name = _text(recorded.get('node_name'))

    if not matching:
        holders = [
            node for node in nodes
            if node_name and _text(node.get('name')).lower() == node_name.lower()
        ]
        if holders:
            held = _text(holders[0].get('uuid')) or 'no UUID'
            return _verdict(
                component, AMBIGUOUS, 'node_name_held',
                f'the recorded node UUID {node_uuid} is gone but the name {node_name!r} is held '
                f'by UUID {held}. Adopting it would rewrite another server\'s endpoint and '
                'registering a second node would duplicate the name; rename or remove that node '
                'before resuming.')
        if recorded_hosts:
            orphans = [host for host in hosts if _text(host.get('uuid')) in recorded_hosts]
            if orphans:
                return _verdict(
                    component, AMBIGUOUS, 'host_records_orphaned',
                    f'the recorded node UUID {node_uuid} is gone but its Host records '
                    f'({", ".join(sorted(recorded_hosts))}) still exist. Remove those records or '
                    'restore the node before resuming; a new registration would leave them '
                    'claiming an inbound nothing owns.')
        return _verdict(
            component, MISSING, 'node_absent',
            f'the Panel holds no node with UUID {node_uuid} and nothing else claims '
            f'{node_name or component}. The component is re-created.', node_uuid)

    node = matching[0]
    # The endpoint is part of the registration: a node the Panel holds under
    # the recorded UUID but at another address or port is the recorded node
    # that drifted, and re-applying the recorded endpoint repairs it. It is
    # never a reason to register a second node.
    expected_address = _text(recorded.get('address'))
    expected_port = recorded.get('port')
    live_address = _text(node.get('address'))
    live_port = node.get('port')
    address_changed = bool(expected_address and live_address and expected_address != live_address)
    port_changed = type(expected_port) is int and live_port is not None \
        and str(live_port) != str(expected_port)
    if address_changed or port_changed:
        return _verdict(
            component, DRIFT, 'node_endpoint_changed',
            f'node {node_uuid} answers at {live_address or "no address"}:{live_port}; the '
            f'checkpoint recorded {expected_address}:{expected_port}. Re-apply the recorded '
            'endpoint.', node_uuid)
    profile_uuid = _text(recorded.get('profile_uuid'))
    if not profile_uuid:
        return _verdict(
            component, AMBIGUOUS, 'profile_identity_unrecorded',
            'the checkpoint names no profile UUID, so the node\'s inbound set cannot be '
            'attributed. Record the profile UUID in the draft before resuming.', node_uuid)
    config_profile = node.get('configProfile')
    config_profile = config_profile if isinstance(config_profile, dict) else {}
    live_profile = _text(config_profile.get('activeConfigProfileUuid'))
    active_inbounds = _inbound_ids(config_profile.get('activeInbounds'))
    profile_inbounds = None
    for profile in profiles:
        if _text(profile.get('uuid')) == profile_uuid:
            profile_inbounds = _ids(profile.get('inbounds'))
            break
    # A checkpoint written before the inbound set was recorded still names the
    # profile, and the profile is the authority on which inbound UUIDs exist.
    # That is a recorded identity read back, not an expectation copied from the
    # node's current association: a node serving anything else has drifted.
    recorded_inbounds = _ids(recorded.get('inbound_uuids'))
    if recorded_inbounds is None:
        recorded_inbounds = profile_inbounds

    if live_profile != profile_uuid:
        if profiles and profile_inbounds is None:
            return _verdict(
                component, AMBIGUOUS, 'profile_absent',
                f'the recorded profile {profile_uuid} no longer exists on the Panel, so the '
                'recorded inbound set cannot be re-applied without inventing one. Restore the '
                'profile or start a new plan.', node_uuid)
        return _verdict(
            component, DRIFT, 'profile_association_changed',
            f'node {node_uuid} serves profile {live_profile or "none"}; the checkpoint recorded '
            f'{profile_uuid}. Re-apply the recorded profile association.', node_uuid)

    if recorded_inbounds is None:
        return _verdict(
            component, AMBIGUOUS, 'inbound_set_unrecorded',
            'the checkpoint names no inbound set, so the node\'s traffic plane cannot be '
            'attributed. Record the inbound UUIDs in the draft before resuming.', node_uuid)
    if set(active_inbounds) != set(recorded_inbounds):
        if profile_inbounds is not None and not set(recorded_inbounds) <= set(profile_inbounds):
            missing = sorted(set(recorded_inbounds) - set(profile_inbounds))
            return _verdict(
                component, AMBIGUOUS, 'inbound_absent',
                f'the recorded profile {profile_uuid} no longer holds inbound(s) '
                f'{", ".join(missing)}; re-applying them would invent a traffic plane. Restore '
                'the profile or start a new plan.', node_uuid)
        return _verdict(
            component, DRIFT, 'inbound_set_changed',
            f'node {node_uuid} serves inbound(s) {", ".join(active_inbounds) or "none"}; the '
            f'checkpoint recorded {", ".join(recorded_inbounds)}. Re-apply the recorded '
            'association.', node_uuid)

    if not recorded_hosts:
        return _verdict(
            component, AMBIGUOUS, 'host_identity_unrecorded',
            'the checkpoint names no Host UUIDs, so the records this node owns cannot be '
            'attributed. Record them in the draft before resuming.', node_uuid)

    claimed = set(recorded_hosts)
    by_uuid = {}
    for host in hosts:
        by_uuid.setdefault(_text(host.get('uuid')), []).append(host)
    owned_inbounds = []
    for host_uuid in recorded_hosts:
        found = by_uuid.get(host_uuid, [])
        if not found:
            holder = _domain_holder(hosts, host_domains, claimed)
            if holder is not None:
                return _verdict(
                    component, AMBIGUOUS, 'host_domain_held_elsewhere',
                    f'the recorded Host {host_uuid} is gone and '
                    f'{_text(holder.get("address")) or _text(holder.get("sni"))} is held by '
                    f'Host {_text(holder.get("uuid")) or "without a UUID"}, which this run cannot '
                    'prove it manages. Rename or remove that Host before resuming.', node_uuid)
            return _verdict(
                component, MISSING, 'host_records_missing',
                f'the Panel holds no Host record with UUID {host_uuid} and no other record '
                'claims its domain. The Host records are re-created.', node_uuid)
        if len(found) > 1:
            return _verdict(
                component, AMBIGUOUS, 'host_uuid_duplicated',
                f'the Panel answered {len(found)} Host records with UUID {host_uuid}. Resolve '
                'the duplicate records before resuming.', node_uuid)
        ownership = host_ownership(found[0])
        if ownership is None:
            return _verdict(
                component, AMBIGUOUS, 'host_unattributable',
                f'Host {host_uuid} carries no profile/inbound/node pairing, so it cannot be '
                'attributed to this node. Repair or remove the record before resuming.', node_uuid)
        owner_profile, owner_inbound, owner_nodes = ownership
        if owner_profile != profile_uuid:
            return _verdict(
                component, AMBIGUOUS, 'host_profile_conflict',
                f'Host {host_uuid} is owned by profile {owner_profile}, not the recorded '
                f'{profile_uuid}. Adopting it would move another profile\'s endpoint; restore '
                'the record or start a new plan.', node_uuid)
        if owner_nodes != (node_uuid,):
            return _verdict(
                component, AMBIGUOUS, 'host_claim_conflict',
                f'Host {host_uuid} is claimed by node(s) {", ".join(owner_nodes) or "none"}, not '
                f'only the recorded {node_uuid}. Rewriting it would move another node\'s '
                'endpoint; repair the record before resuming.', node_uuid)
        if owner_inbound not in set(recorded_inbounds):
            return _verdict(
                component, DRIFT, 'host_inbound_changed',
                f'Host {host_uuid} points at inbound {owner_inbound}, which is not in the '
                'recorded inbound set. Re-apply the Host record.', node_uuid)
        owned_inbounds.append(owner_inbound)

    if sorted(owned_inbounds) != sorted(recorded_inbounds):
        return _verdict(
            component, DRIFT, 'host_coverage_changed',
            'the recorded Host records do not cover exactly the recorded inbounds '
            f'({", ".join(sorted(set(recorded_inbounds) - set(owned_inbounds))) or "no gap"}, '
            f'{", ".join(sorted(owned_inbounds)) or "none"} covered). Re-apply the Host records.',
            node_uuid)

    # A Host record is a dialable endpoint; the domains the plan answered are
    # what it must name. A recorded record that lost one of them is drift, and
    # a domain another record holds is not this run's to rewrite.
    owned_names = set()
    for host_uuid in recorded_hosts:
        host = by_uuid[host_uuid][0]
        owned_names.add(_text(host.get('address')))
        owned_names.add(_text(host.get('sni')))
    missing_domains = [domain for domain in host_domains if domain not in owned_names]
    if missing_domains:
        holder = _domain_holder(hosts, missing_domains, claimed)
        if holder is not None:
            return _verdict(
                component, AMBIGUOUS, 'host_domain_held_elsewhere',
                f'the planned domain(s) {", ".join(missing_domains)} are not on the recorded '
                f'Host records and are held by Host {_text(holder.get("uuid")) or "without a UUID"}, '
                'which this run cannot prove it manages. Rename or remove that Host before '
                'resuming.', node_uuid)
        return _verdict(
            component, DRIFT, 'host_domain_missing',
            f'the recorded Host records do not name the planned domain(s) '
            f'{", ".join(missing_domains)}. Re-apply the Host records.', node_uuid)

    return None


def _security(component, recorded_security, live_security, error):
    """The host's readiness identity: same machine, same role, still ready."""
    if recorded_security is None and live_security is None and not _text(error):
        return None
    if live_security is None:
        if _text(error) in {'unreachable', 'timeout', 'ssh', 'login_refused', 'unreadable'}:
            return _verdict(
                component, UNREACHABLE, 'host_unreachable',
                f'host readiness and security identity could not be read ({_text(error)}). '
                'The draft is unchanged; retry when the host answers.')
        return _verdict(
            component, AMBIGUOUS, 'security_unreadable',
            'no readable security report identifies this host, so its readiness cannot be '
            'attributed to the recorded component. Re-run the host readback before resuming.')
    if not isinstance(live_security, dict):
        return _verdict(
            component, AMBIGUOUS, 'security_malformed',
            'the host security answer is not a report object, so its identity cannot be '
            'attributed. Re-run the host readback before resuming.')
    try:
        status = readiness(live_security)
    except (StateError, ValueError, TypeError) as exc:
        return _verdict(
            component, AMBIGUOUS, 'security_invalid',
            f'the host security report cannot be validated ({exc}). Re-run the host readback '
            'before resuming.')
    schema = live_security.get('schema_version')
    if schema != SUPPORTED_SECURITY_SCHEMA:
        return _verdict(
            component, INCOMPATIBLE, 'security_schema_unsupported',
            f'the host security report is schema {schema!r}; this installer serves schema '
            f'{SUPPORTED_SECURITY_SCHEMA}. Read the host with the matching installer release.')
    if recorded_security:
        recorded_host = _text(recorded_security.get('host_id'))
        live_host = _text(live_security.get('host_id'))
        if recorded_host and live_host and recorded_host != live_host:
            return _verdict(
                component, AMBIGUOUS, 'security_identity_changed',
                f'the security report comes from host {live_host}, not the recorded '
                f'{recorded_host}. The component is not the machine the checkpoint verified; '
                'inspect the host identity before resuming.')
        recorded_role = _text(recorded_security.get('role'))
        live_role = _text(live_security.get('role'))
        if recorded_role and live_role and recorded_role != live_role:
            return _verdict(
                component, DRIFT, 'security_role_changed',
                f'the host now reports role {live_role}, not the recorded {recorded_role}. '
                'Re-apply the host security policy for the recorded role.')
        recorded_revision = _text(recorded_security.get('installer_revision'))
        live_revision = _text(live_security.get('installer_revision'))
        if recorded_revision and live_revision and not _revisions_compatible(recorded_revision, live_revision):
            return _verdict(
                component, DRIFT, 'security_revision_changed',
                f'the host security report was produced by installer {live_revision}, not the '
                f'recorded {recorded_revision}. Re-apply and re-read the host controls.')
    if status == 'failed':
        return _verdict(
            component, DRIFT, 'security_not_ready',
            'the host security report names a required control that is not verified. Re-apply '
            'the host security policy and re-read the controls before resuming.')
    return None


def classify(expectation, live, security=None):
    """Classify one recorded component against the Panel's live answer.

    ``expectation`` is the checkpoint document described in the module
    docstring, ``live`` the Panel answer and ``security`` the optional
    ``{"recorded": ..., "live": ..., "error": ...}`` host readiness answer.
    Raises ``ValueError`` when the expectation is not a document; an
    unreadable live answer is ``unreachable``, never a missing component.
    """
    if not isinstance(expectation, dict):
        raise ValueError('expectation must be an object')
    component = _text(expectation.get('component')) or 'component'
    recorded = expectation.get('recorded')
    if not isinstance(recorded, dict):
        return _verdict(
            component, AMBIGUOUS, 'checkpoint_unrecorded',
            'the draft holds no recorded identity for this component, so nothing can be '
            'compared. Restore the checkpoint or start a new plan.')

    if live is None or not isinstance(live, dict) or live.get('reachable') is False:
        error = ''
        if isinstance(live, dict):
            error = _text(live.get('error'))
        suffix = f' ({error})' if error else ''
        return _verdict(
            component, UNREACHABLE, 'panel_unreachable',
            f'the Panel did not answer the resume readback{suffix}. Nothing was changed and '
            'the draft stays resumable; retry when the Panel is reachable.')

    verdict = _compatibility(component, recorded, live)
    if verdict is not None:
        return verdict

    kind = _text(expectation.get('kind')) or 'node'
    if kind in {'node', 'local-node'}:
        verdict = _node(component, recorded, live)
        if verdict is not None:
            return verdict
    elif kind != 'panel':
        return _verdict(
            component, AMBIGUOUS, 'unknown_component_kind',
            f'the checkpoint names component kind {kind!r}, which this installer cannot '
            'reconcile. Restore the checkpoint or start a new plan.')

    security = security if isinstance(security, dict) else {}
    verdict = _security(
        component,
        security.get('recorded'),
        security.get('live'),
        security.get('error'),
    )
    if verdict is not None:
        return verdict

    return _verdict(
        component, MATCH, 'recorded_state_agrees',
        'the Panel and the host answer the identity, profile, Host and security records the '
        'checkpoint holds.', _text(recorded.get('node_uuid')))


def _read_document():
    try:
        document = json.load(sys.stdin)
    except ValueError as exc:
        raise ValueError('the reconciliation document is not JSON') from exc
    if not isinstance(document, dict):
        raise ValueError('the reconciliation document must be an object')
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description='Classify recorded resume state against the Panel.')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--probe', action='store_true',
                       help='read the Panel and print the live answer')
    modes.add_argument('--classify', action='store_true',
                       help='classify the reconciliation document on standard input')
    parser.add_argument('--credentials', default='/root/gowave-credentials.txt',
                        help='credentials file the Panel login reads (probe mode)')
    parser.add_argument('--state', default='',
                        help='state.json whose schemaVersion the probe reports')
    parser.add_argument('--base-url', default='http://127.0.0.1:3000',
                        help='Panel API base URL (probe mode)')
    parser.add_argument('--profile', action='append', default=[],
                        help='profile UUID whose inbounds the probe reads (repeatable)')
    parser.add_argument('--installer-revision', default='',
                        help='the running installer revision (probe mode)')
    arguments = parser.parse_args(argv)

    try:
        if arguments.classify:
            document = _read_document()
            verdict = classify(document.get('expectation'), document.get('live'), document.get('security'))
            json.dump(verdict.as_dict(), sys.stdout, sort_keys=True)
            sys.stdout.write('\n')
            return 0
        live = resume_live_inventory(
            arguments.credentials,
            state_path=arguments.state or None,
            base_url=arguments.base_url,
            profile_uuids=arguments.profile,
        )
        live['installer_revision'] = arguments.installer_revision or None
        json.dump(live, sys.stdout, sort_keys=True)
        sys.stdout.write('\n')
        return 0
    except (OSError, ValueError, GoWaveAPIError) as exc:
        if arguments.probe:
            # An unread Panel disproves nothing: the shell classifies this as
            # `unreachable` and leaves the draft exactly as it was.
            live = {'reachable': False, 'error': type(exc).__name__}
            json.dump(live, sys.stdout, sort_keys=True)
            sys.stdout.write('\n')
            return 0
        print(f'resume_reconcile: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
