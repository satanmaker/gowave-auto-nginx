#!/usr/bin/env python3
"""Safe effective-control reports, per-host aggregation and outcome reduction.

One report describes one host at one moment. The aggregate is a separate
document because it answers a different question — "may this fleet be called
ready?" — and it is only allowed to answer it from reports that were fresh when
they were combined. A report older than the freshness budget is not evidence
for the current state, and one stale host is enough to refuse the aggregate
rather than let it ride on its siblings' freshness.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys

from modules.deployment_state import DeploymentStore, StateError, _fields, _text

DEFAULT_PATH = Path('/var/lib/gowave-auto-nginx/security-report.json')
DEFAULT_AGGREGATE_PATH = Path('/var/lib/gowave-auto-nginx/security-report-aggregate.json')
CONTROLS = {'firewall', 'ssh_protection', 'security_updates', 'dot'}
STATUSES = {'verified', 'failed', 'skipped', 'unsupported'}
RECOVERY = {'not-needed', 'verified', 'failed', 'unknown'}
READINESS = ('ready', 'ready-with-warnings', 'failed')
DEFAULT_MAX_AGE = 300
WORKER_STATUSES = {'ok', 'fetch_failed', 'invalid'}
FAILURE_REASONS = {'WORKER_READBACK_FAILED', 'REPORT_INVALID'}
CONTROL_NAME = r'[a-zA-Z0-9._-]+'
WORKER_FILE = r'[0-9]{1,6}\.json'
# A report schema stores codes, never captured output. These markers are the
# backstop for the one free-text slot any future schema field could add.
SECRET_MARKERS = ('-----begin', 'private key', 'password=', 'passwd=', 'token=', 'secret=')


class StaleReport(StateError):
    """A report outside the freshness budget; the host and its age travel with it."""

    def __init__(self, host, age, max_age):
        self.host = host
        self.age_seconds = age
        self.max_age = max_age
        where = f'{age:.0f} seconds old' if age >= 0 else f'{-age:.0f} seconds in the future'
        super().__init__(f'security report for {host} is stale: {where} (limit {max_age} seconds)')


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def redacted(document):
    """True when no string in the document can carry a credential body."""
    return not any(marker in value.lower() for value in _strings(document) for marker in SECRET_MARKERS)


def require_redacted(document):
    if not redacted(document):
        raise StateError('security report would carry secret material')
    return document


def observed_at(document):
    """The validated, timezone-aware timestamp of a report or aggregate."""
    try:
        observed = datetime.fromisoformat(document['observed_at'].replace('Z', '+00:00'))
        if observed.tzinfo is None:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError('invalid observation timestamp') from exc
    return observed


def age_seconds(document, *, now=None):
    """How old the observation is, in seconds; negative for a future timestamp."""
    current = now or datetime.now(timezone.utc)
    return (current - observed_at(document)).total_seconds()


def check_freshness(document, *, host, now=None, max_age=DEFAULT_MAX_AGE):
    age = age_seconds(document, now=now)
    if age < 0 or age > max_age:
        raise StaleReport(host, age, max_age)
    return age


def schema(report):
    """Structural validation only: freshness is a separate, time-relative check."""
    _fields(report, {'schema_version', 'host_id', 'role', 'installer_revision', 'observed_at', 'controls'})
    if type(report['schema_version']) is not int or report['schema_version'] != 1:
        raise StateError('unsupported security report schema')
    _text(report['host_id'], CONTROL_NAME, 253)
    _text(report['installer_revision'], CONTROL_NAME, 64)
    if report['role'] not in {'aio', 'panel-only', 'worker'}:
        raise StateError('invalid security report role')
    observed_at(report)
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


def validate(report, *, now=None, max_age=DEFAULT_MAX_AGE):
    """A structurally valid report that is also fresh enough to be evidence."""
    schema(report)
    check_freshness(report, host=report['host_id'], now=now, max_age=max_age)
    return require_redacted(report)


def reduction(report):
    """The verdict a structurally valid report carries, independent of its age.

    Required and best-effort are not two names for the same severity: a
    required control that is not `verified` blocks the host, while a best-effort
    outcome that was rolled back and proven is a warning. The recovery outcome
    is a third question, and an unproven one blocks under either policy.
    """
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


def readiness(report, *, now=None, max_age=DEFAULT_MAX_AGE):
    return reduction(validate(report, now=now, max_age=max_age))


def blocking_controls(report):
    """Required controls that are not `verified`, in a stable order."""
    return [name for name in sorted(report['controls'])
            if report['controls'][name]['policy'] == 'required'
            and report['controls'][name]['status'] != 'verified']


def warning_controls(report):
    """Best-effort controls that failed but left a proven, working host."""
    return [name for name in sorted(report['controls'])
            if report['controls'][name]['policy'] == 'best-effort'
            and report['controls'][name]['status'] != 'verified'
            and report['controls'][name]['recovery'] == 'verified']


def deciding_control(report):
    """The control that keeps this report from `ready`, or None when it is ready.

    The order matches `reduction`: a required control first, then an unproven
    recovery under any policy, then the tolerated best-effort outcome that makes
    a `ready-with-warnings` verdict.
    """
    for name in sorted(report['controls']):
        control = report['controls'][name]
        if control['policy'] == 'required' and control['status'] != 'verified':
            return name
    for name in sorted(report['controls']):
        if report['controls'][name]['recovery'] in {'failed', 'unknown'}:
            return name
    for name in sorted(report['controls']):
        control = report['controls'][name]
        if control['policy'] == 'best-effort' and control['status'] != 'verified':
            return name
    return None


def _weakest(rows):
    """The weakest verdict among (host, verdict, control) rows, and who decided it."""
    severity = {name: index for index, name in enumerate(READINESS)}
    verdict, decided_by = 'ready', None
    for host, host_verdict, control in rows:
        if severity[host_verdict] > severity[verdict]:
            verdict = host_verdict
            decided_by = {'host': host, 'control': control, 'readiness': host_verdict}
    return verdict, decided_by


def combine(master, workers, *, now=None, max_age=DEFAULT_MAX_AGE):
    """Build the aggregate document, or refuse it.

    `workers` maps a planned host name to either a report or an explicit
    `{'status': 'fetch_failed' | 'invalid'}` marker. Every report is checked
    against its own timestamp before it is counted: a report that predates the
    mutation it describes is not evidence for the current state, and mixing one
    stale host into an otherwise fresh aggregate would let it ride on its
    siblings' freshness. The refusal is a `StaleReport`, which carries the host
    and its age so the operator learns which host to re-read.
    """
    current = now or datetime.now(timezone.utc)
    validate(master, now=current, max_age=max_age)
    entries = {}
    for name, entry in workers.items():
        _text(name, CONTROL_NAME, 253)
        if isinstance(entry, dict) and entry.get('status') in WORKER_STATUSES - {'ok'}:
            entries[name] = {'status': entry['status'],
                             'reason_code': ('WORKER_READBACK_FAILED' if entry['status'] == 'fetch_failed'
                                             else 'REPORT_INVALID')}
            continue
        report = entry.get('report') if isinstance(entry, dict) and entry.get('status') == 'ok' else entry
        try:
            validate(report, now=current, max_age=max_age)
        except StaleReport as stale:
            # A stale report is refused, not rounded down to `invalid`: the host
            # did answer, and the operator needs its age to know what to re-read.
            raise StaleReport(name, stale.age_seconds, max_age) from None
        except StateError:
            entries[name] = {'status': 'invalid', 'reason_code': 'REPORT_INVALID'}
            continue
        entries[name] = {'status': 'ok', 'readiness': reduction(report),
                         'observed_at': report['observed_at'], 'report': report,
                         'blocking': blocking_controls(report),
                         'warnings': warning_controls(report)}
    document = {'schema_version': 1,
                'observed_at': current.isoformat().replace('+00:00', 'Z'),
                'master': master, 'workers': entries}
    verdict, decided_by = aggregate_readiness(document)
    document.update({'readiness': verdict, 'decided_by': decided_by})
    return validate_aggregate(document)


def aggregate_readiness(document):
    """The weakest of the aggregate's hosts, naming the host and control.

    A host whose report is missing has no control to name, so the report itself
    is named as the deciding entry. The order is fixed — the Master first, then
    the planned host names in sorted order — so two runs over the same evidence
    name the same host.
    """
    rows = [('master', reduction(document['master']), deciding_control(document['master']))]
    for name in sorted(document['workers']):
        entry = document['workers'][name]
        if entry.get('status') == 'ok':
            rows.append((name, entry['readiness'], deciding_control(entry['report'])))
        else:
            rows.append((name, 'failed', 'security_report'))
    return _weakest(rows)


AGGREGATE_FIELDS = {'schema_version', 'observed_at', 'readiness', 'decided_by', 'master', 'workers'}
AGGREGATE_ENTRY_FIELDS = {'status', 'readiness', 'observed_at', 'report', 'blocking', 'warnings'}
AGGREGATE_FAILURE_FIELDS = {'status', 'reason_code'}


def validate_aggregate(document):
    """Validate an aggregate without applying a freshness window.

    An aggregate is a historical document: it records the timestamps it was
    built from, and re-reading it later must not turn it invalid. What it must
    never do is disagree with its own contents, which is why the stored verdict,
    the deciding host and every per-host reduction are recomputed here.
    """
    _fields(document, AGGREGATE_FIELDS)
    if type(document['schema_version']) is not int or document['schema_version'] != 1:
        raise StateError('unsupported security report aggregate schema')
    observed_at(document)
    if document['readiness'] not in READINESS:
        raise StateError('invalid aggregate readiness')
    schema(document['master'])
    decided = document['decided_by']
    if decided is not None:
        _fields(decided, {'host', 'control', 'readiness'})
        _text(decided['host'], CONTROL_NAME, 253)
        if decided['control'] != 'security_report' and decided['control'] not in CONTROLS:
            raise StateError('invalid deciding control')
        if decided['readiness'] not in READINESS:
            raise StateError('invalid deciding readiness')
    if not isinstance(document['workers'], dict):
        raise StateError('invalid Worker collection')
    for name, entry in document['workers'].items():
        _text(name, CONTROL_NAME, 253)
        status = entry.get('status') if isinstance(entry, dict) else None
        if status == 'ok':
            _fields(entry, AGGREGATE_ENTRY_FIELDS)
            schema(entry['report'])
            if entry['readiness'] not in READINESS or entry['readiness'] != reduction(entry['report']):
                raise StateError('Worker readiness disagrees with its controls')
            if entry['observed_at'] != entry['report']['observed_at']:
                raise StateError('Worker timestamp disagrees with its report')
            observed_at(entry)
            for key in ('blocking', 'warnings'):
                if not isinstance(entry[key], list) or len(set(entry[key])) != len(entry[key]):
                    raise StateError('invalid Worker control list')
                for control in entry[key]:
                    if control not in CONTROLS:
                        raise StateError('invalid Worker control name')
            if entry['blocking'] != blocking_controls(entry['report']):
                raise StateError('Worker blocking controls disagree with its report')
            if entry['warnings'] != warning_controls(entry['report']):
                raise StateError('Worker warning controls disagree with its report')
        elif status in WORKER_STATUSES - {'ok'}:
            _fields(entry, AGGREGATE_FAILURE_FIELDS)
            if entry['reason_code'] not in FAILURE_REASONS:
                raise StateError('invalid Worker report reason')
        else:
            raise StateError('invalid Worker report entry')
    verdict, decided_by = aggregate_readiness(document)
    if document['readiness'] != verdict or document['decided_by'] != decided_by:
        raise StateError('aggregate readiness disagrees with its hosts')
    return require_redacted(document)


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
    """One report per path. Reading never rewrites; saving replaces atomically."""

    def __init__(self, path=DEFAULT_PATH, *, owner_uid=0):
        super().__init__(path, owner_uid=owner_uid)

    def _validate_directory(self, info):
        if info.st_uid != self.owner_uid or info.st_mode & 0o022:
            raise StateError('security report directory must be owned and not writable by others')

    def _payload(self, document):
        require_redacted(document)
        return json.dumps(document, sort_keys=True).encode() + b'\n'

    def _write(self, payload):
        # temp sibling -> fsync file -> rename -> fsync directory. The rename is
        # what makes a rerun a new report rather than a patched old one: a
        # reader sees the previous document or the new one, never a mixture.
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

    def _load(self, checker):
        with self._directory() as directory:
            descriptor = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
                self._private(stream.fileno())
                raw = stream.read(65537)
                if len(raw) > 65536:
                    raise StateError('security report too large')
                return checker(json.loads(raw))

    def save(self, report, *, now=None):
        validate(report, now=now)
        self._write(self._payload(report))

    def load(self, *, now=None, max_age=DEFAULT_MAX_AGE):
        return self._load(lambda document: validate(document, now=now, max_age=max_age))


class AggregateStore(SecurityReportStore):
    """The fleet document. It carries its own timestamps, so reading it is timeless."""

    def __init__(self, path=DEFAULT_AGGREGATE_PATH, *, owner_uid=0):
        super().__init__(path, owner_uid=owner_uid)

    def save(self, aggregate):
        validate_aggregate(aggregate)
        self._write(self._payload(aggregate))

    def load(self):
        return self._load(validate_aggregate)


def _worker_documents(directory, request):
    """Read the raw readbacks the caller collected, one numbered file each.

    A file the caller could not fetch is absent, and an unparseable file is not
    guessed at: both become explicit failure markers whose text is a fixed code,
    so arbitrary host output never reaches the aggregate.
    """
    if not isinstance(request, dict):
        raise StateError('invalid aggregate request')
    _fields(request, {'workers'})
    if not isinstance(request['workers'], list):
        raise StateError('invalid Worker request list')
    root = Path(directory)
    workers = {}
    for item in request['workers']:
        _fields(item, {'name', 'file'})
        _text(item['name'], CONTROL_NAME, 253)
        _text(item['file'], WORKER_FILE, 32)
        path = root / item['file']
        if path.is_symlink() or not path.is_file():
            workers[item['name']] = {'status': 'fetch_failed'}
            continue
        try:
            workers[item['name']] = {'status': 'ok', 'report': json.loads(path.read_text(encoding='utf-8'))}
        except (OSError, ValueError):
            workers[item['name']] = {'status': 'invalid'}
    return workers


def main(argv=None):
    parser = argparse.ArgumentParser(description='Validate, aggregate and reduce security reports.')
    parser.add_argument('--check', action='store_true', help='answer whether the report at --path is fresh')
    parser.add_argument('--aggregate', action='store_true', help='combine --master with the collected Worker reports')
    parser.add_argument('--path', type=Path, default=None)
    parser.add_argument('--master', type=Path, default=DEFAULT_PATH)
    parser.add_argument('--workers', type=Path, default=None)
    parser.add_argument('--owner-uid', type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if args.check:
            store = SecurityReportStore(args.path or DEFAULT_PATH, owner_uid=args.owner_uid)
            report = store.load()
            print(json.dumps({'status': 'fresh', 'host_id': report['host_id'],
                              'age_seconds': round(age_seconds(report)),
                              'readiness': reduction(report)}))
            return 0
        if args.aggregate:
            if args.workers is None:
                raise StateError('an aggregate needs the Worker readback directory')
            master = SecurityReportStore(args.master, owner_uid=args.owner_uid).load()
            workers = _worker_documents(args.workers, json.load(sys.stdin))
            document = combine(master, workers)
            store = AggregateStore(args.path or DEFAULT_AGGREGATE_PATH, owner_uid=args.owner_uid)
            store.save(document)
            print(json.dumps({'status': document['readiness'], 'readiness': document['readiness'],
                              'decided_by': document['decided_by'], 'path': str(store.path)}))
            return 0 if document['readiness'] in {'ready', 'ready-with-warnings'} else 1
        raise StateError('choose --check or --aggregate')
    except StaleReport as stale:
        print(json.dumps({'status': 'refused', 'error': str(stale)}))
        print(str(stale), file=sys.stderr)
        return 1
    except (StateError, OSError, ValueError) as error:
        print(json.dumps({'status': 'invalid', 'error': str(error)}))
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
