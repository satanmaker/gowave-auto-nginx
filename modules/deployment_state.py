#!/usr/bin/env python3
"""Versioned, private deployment drafts; resource rollback journals remain separate.

The wizard drives this module through its command line, because a draft that
only one process could reach would not survive the restart it exists for. Every
mode reads one JSON document from standard input and answers with JSON on
standard output, so no secret and no answer travels through `argv`:

    --load                     print the draft; exit 3 when there is none
    --save --expected-revision print the draft that replaced revision N
    --plan [--reviewed]        write an accepted plan, keeping checkpoints
    --checkpoint IDENTITY      merge one checkpoint and print it
    --expectation IDENTITY     print what one checkpoint recorded, for a resume
    --discard                  forget the draft; absent draft is still success

Exit codes are the same in every mode: 0 success, 1 rejected input, 3 no
draft, 4 a concurrent writer, a stale revision or another operation. A crash
between two calls leaves a draft the next invocation can load, which is the
whole point; nothing here compensates a deployment.
"""
import argparse
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

DEFAULT_PATH = Path('/var/lib/gowave-auto-nginx/deployment/active.json')
EXIT_OK = 0
EXIT_INVALID = 1
EXIT_ABSENT = 3
EXIT_CONFLICT = 4
MAX_DOCUMENT = 1024 * 1024
PLAN_FIELDS = {'kind', 'topology', 'language', 'answers', 'nodes', 'installer_revision'}
ANSWER_FIELDS = {
    'name', 'address', 'ssh_user', 'ssh_port', 'node_port', 'primary_domain',
    'reality_domain', 'vision_domain', 'cover_domain', 'cover_www', 'country',
    'email', 'dot_policy',
}
CHECKPOINT_FIELDS = {
    'state', 'stage', 'attempt', 'node_uuid', 'profile_uuid', 'host_uuids',
    'registration', 'readiness', 'cleanup', 'recovery', 'reason_code',
}
STATES = {'pending', 'running', 'verified', 'failed', 'indeterminate', 'skipped'}
STAGES = {
    'pending', 'preflight', 'registration', 'prerequisites', 'security', 'acme',
    'deployment', 'verification', 'cleanup', 'recovery', 'complete',
}


class StateError(ValueError):
    pass


class StateConflict(StateError):
    pass


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys():
        raise StateError('missing state fields')
    if value.keys() - set(required) - set(optional):
        raise StateError('unexpected state fields')


def _text(value, pattern, limit=253):
    if not isinstance(value, str) or len(value) > limit or not re.fullmatch(pattern, value):
        raise StateError('invalid state value')


def _answers(answers):
    _fields(answers, (), ANSWER_FIELDS)
    for key, value in answers.items():
        if key in {'ssh_port', 'node_port'}:
            if type(value) is not int or not 1 <= value <= 65535:
                raise StateError('invalid port')
        elif key == 'cover_www':
            if type(value) is not bool:
                raise StateError('invalid cover alias choice')
        elif key == 'dot_policy':
            if value not in {'off', 'best-effort', 'required'}:
                raise StateError('invalid DNS policy')
        elif key == 'country':
            _text(value, r'(?:[A-Z]{2})?')
        elif key.endswith('_domain'):
            _text(value, r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|')
        elif key == 'address':
            _text(value, r'[a-zA-Z0-9.:-]+')
        elif key == 'ssh_user':
            _text(value, r'[a-z_][a-z0-9_-]*', 32)
        elif key == 'email':
            _text(value, r'[^\s@]+@[^\s@]+')
        else:
            _text(value, r'[\w .-]+', 64)


def plan_digest(document):
    plan = {key: document[key] for key in ('kind', 'topology', 'language', 'answers', 'nodes')}
    return hashlib.sha256(json.dumps(plan, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def validate(document):
    _fields(document, {
        'schema_version', 'revision', 'installer_revision', 'operation_id', 'kind',
        'topology', 'language', 'answers', 'nodes', 'reviewed_digest', 'checkpoints',
    })
    if type(document['schema_version']) is not int or document['schema_version'] != 1:
        raise StateError('unsupported deployment schema')
    if type(document['revision']) is not int or document['revision'] < 1:
        raise StateError('invalid revision')
    _text(document['installer_revision'], r'[a-zA-Z0-9._-]+', 64)
    _text(document['operation_id'], r'[a-zA-Z0-9_-]+', 64)
    if document['kind'] not in {'install', 'node_add'}:
        raise StateError('invalid operation kind')
    if document['topology'] not in {'aio', 'multi-node', 'panel-only'}:
        raise StateError('invalid topology')
    if document['language'] not in {'ru', 'en'}:
        raise StateError('invalid language')
    _answers(document['answers'])
    nodes = document['nodes']
    if not isinstance(nodes, dict) or len(nodes) > 100:
        raise StateError('invalid node collection')
    for identity, answers in nodes.items():
        _text(identity, r'[a-zA-Z0-9_-]+', 64)
        _answers(answers)
    checkpoints = document['checkpoints']
    if not isinstance(checkpoints, dict):
        raise StateError('invalid checkpoints')
    for identity, checkpoint in checkpoints.items():
        if identity not in {'panel', 'local-node'} | nodes.keys():
            raise StateError('unknown checkpoint identity')
        _fields(checkpoint, {'state', 'stage', 'attempt'}, CHECKPOINT_FIELDS)
        if checkpoint['state'] not in STATES or checkpoint['stage'] not in STAGES:
            raise StateError('invalid checkpoint phase')
        if type(checkpoint['attempt']) is not int or checkpoint['attempt'] < 0:
            raise StateError('invalid checkpoint attempt')
        for key, value in checkpoint.items():
            if key in {'registration', 'readiness', 'cleanup', 'recovery'}:
                if value not in STATES | {'not-needed', 'unknown'}:
                    raise StateError('invalid checkpoint outcome')
            elif key in {'node_uuid', 'profile_uuid'}:
                _text(value, r'[a-fA-F0-9-]{36}', 36)
            elif key == 'host_uuids':
                if not isinstance(value, list) or len(value) > 100:
                    raise StateError('invalid host identities')
                for uuid in value:
                    _text(uuid, r'[a-fA-F0-9-]{36}', 36)
            elif key == 'reason_code':
                _text(value, r'[A-Z][A-Z0-9_]*', 64)
    digest = document['reviewed_digest']
    if digest is not None and digest != plan_digest(document):
        raise StateError('reviewed plan has changed')
    return document


class DeploymentStore:
    def __init__(self, path=DEFAULT_PATH, *, owner_uid=0):
        self.path = Path(path)
        if not self.path.is_absolute() or '..' in self.path.parts:
            raise StateError('deployment path must be absolute without traversal')
        self.owner_uid = owner_uid

    @contextmanager
    def _directory(self):
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.path.parent.parts[1:]:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                except FileNotFoundError:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                info = os.fstat(descriptor)
                if info.st_uid not in {0, self.owner_uid} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                    raise StateError('unsafe deployment ancestor')
            info = os.fstat(descriptor)
            self._validate_directory(info)
            yield descriptor
        finally:
            os.close(descriptor)

    def _validate_directory(self, info):
        if info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise StateError('deployment directory must be private and owned')

    def _private(self, descriptor):
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise StateError('deployment file must be private, regular and owned')

    def _read(self, directory):
        try:
            descriptor = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
            self._private(stream.fileno())
            raw = stream.read(MAX_DOCUMENT + 1)
            if len(raw) > MAX_DOCUMENT:
                raise StateError('deployment document too large')
            return validate(json.loads(raw))

    @contextmanager
    def _lock(self, directory):
        descriptor = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        try:
            self._private(descriptor)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StateConflict('deployment writer is busy') from exc
            yield
        finally:
            os.close(descriptor)

    def load(self):
        with self._directory() as directory:
            return self._read(directory)

    def discard(self):
        # Removing the draft is how an operator abandons it: the deployment it
        # described stays exactly as it is, so nothing here compensates.
        with self._directory() as directory, self._lock(directory):
            try:
                os.unlink(self.path.name, dir_fd=directory)
            except FileNotFoundError:
                return False
            os.fsync(directory)
            return True

    def save(self, document, *, expected_revision):
        candidate = copy.deepcopy(document)
        candidate['revision'] = expected_revision + 1
        validate(candidate)
        payload = json.dumps(candidate, sort_keys=True, ensure_ascii=True).encode() + b'\n'
        if len(payload) > MAX_DOCUMENT:
            raise StateError('deployment document too large')
        with self._directory() as directory, self._lock(directory):
            current = self._read(directory)
            if (current['revision'] if current else 0) != expected_revision:
                raise StateConflict('deployment revision changed')
            if current and current['operation_id'] != candidate['operation_id']:
                raise StateConflict('another deployment is active')
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
        return candidate


def _read_document():
    raw = sys.stdin.read(MAX_DOCUMENT + 1)
    if len(raw) > MAX_DOCUMENT:
        raise StateError('deployment document too large')
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise StateError('deployment document is not JSON') from exc
    if not isinstance(document, dict):
        raise StateError('deployment document must be an object')
    return document


def _write_document(document):
    sys.stdout.write(json.dumps(document, sort_keys=True, ensure_ascii=True) + '\n')
    sys.stdout.flush()


def _plan_fields(document, stored):
    # Only the accepted answers and the reviewed plan come from the wizard;
    # the operation identity belongs to the draft, and a plan that arrives
    # under another installer revision is not the plan this draft recorded.
    _fields(document, PLAN_FIELDS, ('operation_id',))
    if stored and stored['installer_revision'] != document['installer_revision']:
        raise StateConflict('draft belongs to another installer revision')
    operation_id = document.get('operation_id') or (stored['operation_id'] if stored else secrets.token_hex(16))
    _text(operation_id, r'[a-zA-Z0-9_-]+', 64)
    if stored and operation_id != stored['operation_id']:
        raise StateConflict('another deployment is active')
    nodes = document['nodes']
    if not isinstance(nodes, dict):
        raise StateError('invalid node collection')
    checkpoints = {} if stored is None else {
        identity: checkpoint for identity, checkpoint in stored['checkpoints'].items()
        if identity in {'panel', 'local-node'} | nodes.keys()
    }
    return {
        'schema_version': 1,
        'revision': stored['revision'] if stored else 0,
        'installer_revision': document['installer_revision'],
        'operation_id': operation_id,
        'kind': document['kind'],
        'topology': document['topology'],
        'language': document['language'],
        'answers': document['answers'],
        'nodes': nodes,
        'reviewed_digest': None,
        'checkpoints': checkpoints,
    }


def checkpoint_expectation(document, identity):
    """What one checkpoint recorded, as a resume reconciles it.

    The document is the draft the interrupted run left, so every field here is
    something that run accepted or observed. The plan answers name the domains a
    node owns and the label the Panel registered; the checkpoint supplies the
    identities the Panel issued. Nothing is filled in from the live Panel: a
    resume compares this answer with the Panel's, and inventing an expectation
    from the answer would make every comparison pass.
    """
    if identity not in {'panel', 'local-node'} | document['nodes'].keys():
        raise StateError('unknown checkpoint identity')
    checkpoint = document['checkpoints'].get(identity)
    if checkpoint is None:
        raise StateError('checkpoint is absent')
    kind = 'panel' if identity == 'panel' else ('local-node' if identity == 'local-node' else 'node')
    recorded = {key: checkpoint[key] for key in ('state', 'stage', 'attempt')}
    for key in ('node_uuid', 'profile_uuid', 'host_uuids', 'reason_code', 'recovery'):
        if key in checkpoint:
            recorded[key] = checkpoint[key]
    recorded['installer_revision'] = document['installer_revision']
    answers = document['nodes'].get(identity, {}) if kind == 'node' else document['answers']
    if answers.get('name'):
        recorded['node_name'] = answers['name']
    domains = [
        answers[key] for key in ('primary_domain', 'reality_domain', 'vision_domain')
        if answers.get(key)
    ]
    if domains:
        recorded['host_domains'] = list(dict.fromkeys(domains))
    return {'component': identity, 'kind': kind, 'recorded': recorded}


def _checkpoint_update(stored, identity, update):
    if stored is None:
        raise FileNotFoundError('no deployment draft to checkpoint')
    if not isinstance(update, dict) or set(update) - CHECKPOINT_FIELDS:
        raise StateError('invalid checkpoint fields')
    if identity not in {'panel', 'local-node'} | stored['nodes'].keys():
        raise StateError('unknown checkpoint identity')
    checkpoint = dict(stored['checkpoints'].get(identity, {'state': 'pending', 'stage': 'pending', 'attempt': 0}))
    checkpoint.update(update)
    document = copy.deepcopy(stored)
    document['checkpoints'][identity] = checkpoint
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read and write the private deployment draft.')
    parser.add_argument('--path', type=Path, default=DEFAULT_PATH, help='draft path (default: the system draft)')
    parser.add_argument('--owner-uid', type=int, default=os.geteuid(), help='expected owner; must be the current user')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--load', action='store_true', help='print the stored draft')
    modes.add_argument('--save', action='store_true', help='replace the draft with the document on stdin')
    modes.add_argument('--plan', action='store_true', help='write the plan document on stdin as the draft')
    modes.add_argument('--checkpoint', metavar='IDENTITY', help='merge the checkpoint on stdin')
    modes.add_argument('--expectation', metavar='IDENTITY',
                       help='print what one checkpoint recorded, for a resume')
    modes.add_argument('--discard', action='store_true', help='remove the draft')
    parser.add_argument('--expected-revision', type=int, default=None, help='revision the caller last read')
    parser.add_argument('--reviewed', action='store_true', help='mark the plan as authorized by the operator')
    arguments = parser.parse_args(argv)

    try:
        if arguments.owner_uid != os.geteuid():
            raise StateError('draft owner must be the current user')
        store = DeploymentStore(arguments.path, owner_uid=arguments.owner_uid)
        if arguments.load:
            document = store.load()
            if document is None:
                return EXIT_ABSENT
            _write_document(document)
        elif arguments.save:
            if arguments.expected_revision is None:
                raise StateError('--save needs --expected-revision')
            _write_document(store.save(_read_document(), expected_revision=arguments.expected_revision))
        elif arguments.plan:
            stored = store.load()
            document = _plan_fields(_read_document(), stored)
            if arguments.reviewed:
                document['reviewed_digest'] = plan_digest(document)
            _write_document(store.save(document, expected_revision=document['revision']))
        elif arguments.checkpoint is not None:
            stored = store.load()
            document = _checkpoint_update(stored, arguments.checkpoint, _read_document())
            _write_document(store.save(document, expected_revision=stored['revision']))
        elif arguments.expectation is not None:
            document = store.load()
            if document is None:
                raise FileNotFoundError('no deployment draft to reconcile')
            _write_document(checkpoint_expectation(document, arguments.expectation))
        else:
            store.discard()
    except FileNotFoundError as exc:
        print(f'deployment_state: {exc}', file=sys.stderr)
        return EXIT_ABSENT
    except StateConflict as exc:
        print(f'deployment_state: {exc}', file=sys.stderr)
        return EXIT_CONFLICT
    except StateError as exc:
        print(f'deployment_state: {exc}', file=sys.stderr)
        return EXIT_INVALID
    except OSError as exc:
        print(f'deployment_state: {exc.strerror or exc}', file=sys.stderr)
        return EXIT_INVALID
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
