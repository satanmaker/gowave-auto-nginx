#!/usr/bin/env python3
"""Versioned, private deployment drafts; resource rollback journals remain separate."""
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

DEFAULT_PATH = Path('/var/lib/gowave-auto-nginx/deployment/active.json')
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
            raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise StateError('deployment document too large')
            return validate(json.loads(raw))

    def load(self):
        with self._directory() as directory:
            return self._read(directory)

    def save(self, document, *, expected_revision):
        candidate = copy.deepcopy(document)
        candidate['revision'] = expected_revision + 1
        validate(candidate)
        payload = json.dumps(candidate, sort_keys=True, ensure_ascii=True).encode() + b'\n'
        if len(payload) > 1024 * 1024:
            raise StateError('deployment document too large')
        with self._directory() as directory:
            lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            try:
                self._private(lock)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise StateConflict('deployment writer is busy') from exc
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
            finally:
                os.close(lock)
        return candidate
