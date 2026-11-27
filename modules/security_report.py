#!/usr/bin/env python3
"""Safe effective-control reports and final deployment outcome reduction."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets

from modules.deployment_state import DeploymentStore, StateError, _fields, _text

DEFAULT_PATH = Path('/var/lib/gowave-auto-nginx/security-report.json')
CONTROLS = {'firewall', 'ssh_protection', 'security_updates', 'dot'}
STATUSES = {'verified', 'failed', 'skipped', 'unsupported'}
RECOVERY = {'not-needed', 'verified', 'failed', 'unknown'}


def validate(report, *, now=None, max_age=300):
    _fields(report, {'schema_version', 'host_id', 'role', 'installer_revision', 'observed_at', 'controls'})
    if type(report['schema_version']) is not int or report['schema_version'] != 1:
        raise StateError('unsupported security report schema')
    _text(report['host_id'], r'[a-zA-Z0-9._-]+', 253)
    _text(report['installer_revision'], r'[a-zA-Z0-9._-]+', 64)
    if report['role'] not in {'aio', 'panel-only', 'worker'}:
        raise StateError('invalid security report role')
    try:
        observed = datetime.fromisoformat(report['observed_at'].replace('Z', '+00:00'))
        if observed.tzinfo is None:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError('invalid observation timestamp') from exc
    current = now or datetime.now(timezone.utc)
    age = (current - observed).total_seconds()
    if age < 0 or age > max_age:
        raise StateError('stale or future security report')
    _fields(report['controls'], CONTROLS)
    for name, control in report['controls'].items():
        _fields(control, {'policy', 'status', 'reason_code', 'recovery', 'evidence_codes'})
        policies = {'off', 'best-effort', 'required'} if name == 'dot' else {'required'}
        if control['policy'] not in policies or control['status'] not in STATUSES:
            raise StateError('invalid control policy or status')
        if control['recovery'] not in RECOVERY:
            raise StateError('invalid recovery outcome')
        _text(control['reason_code'], r'[A-Z][A-Z0-9_]*', 64)
        if not isinstance(control['evidence_codes'], list) or len(control['evidence_codes']) > 32:
            raise StateError('invalid control evidence')
        for code in control['evidence_codes']:
            _text(code, r'[A-Z][A-Z0-9_]*', 64)
        if control['policy'] == 'off' and control['status'] != 'skipped':
            raise StateError('disabled control must be skipped')
        if control['status'] == 'verified' and control['recovery'] != 'not-needed':
            raise StateError('verified control cannot require recovery')
    return report


def readiness(report, *, now=None, max_age=300):
    validate(report, now=now, max_age=max_age)
    warning = False
    for control in report['controls'].values():
        if control['policy'] == 'required' and control['status'] != 'verified':
            return 'failed'
        if control['recovery'] in {'failed', 'unknown'}:
            return 'failed'
        if control['policy'] == 'best-effort' and control['status'] != 'verified':
            if control['status'] == 'failed' and control['recovery'] != 'verified':
                return 'failed'
            warning = True
    return 'ready-with-warnings' if warning else 'ready'


def dot_control(result):
    """Map the DNS-over-TLS helper's report onto one control entry.

    The helper answers three separate questions: which policy was requested,
    whether it took effect, and whether the host was put back. The report keeps
    them apart, so a failed policy whose rollback was proven is `failed` with
    `recovery == 'verified'` — never `verified`, which the validator reserves
    for a control that needed no recovery at all.
    """
    policy = result.get('policy') or result.get('dot')
    if policy not in {'off', 'best-effort', 'required'}:
        raise StateError('invalid DNS-over-TLS policy in helper report')
    if result.get('status') == 'configured':
        status, reason = ('skipped', 'DOT_DISABLED') if policy == 'off' else ('verified', 'DOT_APPLIED')
        recovery = 'not-needed'
    elif result.get('status') == 'failed_rolled_back':
        status, reason, recovery = 'failed', 'DOT_NOT_APPLIED', 'verified'
    elif result.get('status') == 'failed_unverified':
        status, reason, recovery = 'failed', 'DOT_RESTORE_UNPROVEN', 'failed'
    else:
        raise StateError('unknown DNS-over-TLS helper status: ' + str(result.get('status')))
    return {'policy': policy, 'status': status, 'reason_code': reason,
            'recovery': recovery, 'evidence_codes': ['DOT_HELPER']}


def final_exit(panel, nodes):
    def complete(component):
        _fields(component, {'registration', 'readiness', 'cleanup', 'recovery'})
        if component['registration'] not in {'verified', 'failed', 'indeterminate', 'pending'}:
            raise StateError('invalid registration outcome')
        if component['readiness'] not in {'verified', 'ready-with-warnings', 'failed', 'indeterminate', 'pending'}:
            raise StateError('invalid readiness outcome')
        if component['cleanup'] not in {'verified', 'not-needed', 'failed', 'indeterminate', 'pending'}:
            raise StateError('invalid cleanup outcome')
        if component['recovery'] not in RECOVERY:
            raise StateError('invalid recovery outcome')
        return (
            component['registration'] == 'verified'
            and component['readiness'] in {'verified', 'ready-with-warnings'}
            and component['cleanup'] in {'verified', 'not-needed'}
            and component['recovery'] in {'not-needed', 'verified'}
        )
    if not isinstance(nodes, list):
        raise StateError('invalid final node collection')
    panel_ready = complete(panel)
    nodes_ready = [complete(node) for node in nodes]
    if not panel_ready:
        return 1
    return 0 if all(nodes_ready) else 2


class SecurityReportStore(DeploymentStore):
    def __init__(self, path=DEFAULT_PATH, *, owner_uid=0):
        super().__init__(path, owner_uid=owner_uid)

    def _validate_directory(self, info):
        if info.st_uid != self.owner_uid or info.st_mode & 0o022:
            raise StateError('security report directory must be owned and not writable by others')

    def save(self, report, *, now=None):
        validate(report, now=now)
        payload = json.dumps(report, sort_keys=True).encode() + b'\n'
        with self._directory() as directory:
            temporary = f'.{self.path.name}.{secrets.token_hex(12)}.tmp'
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def load(self, *, now=None, max_age=300):
        with self._directory() as directory:
            descriptor = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
                self._private(stream.fileno())
                raw = stream.read(65537)
                if len(raw) > 65536:
                    raise StateError('security report too large')
                return validate(json.loads(raw), now=now, max_age=max_age)
