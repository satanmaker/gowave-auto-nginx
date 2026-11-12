"""Local ACME fixture: a trusted test CA plus Pebble, pinned and scoped.

The fixture exists so the real Certbot path can be exercised without touching
production Let's Encrypt. Three trust boundaries are kept separate:

* the fixture CA signs the Pebble HTTPS endpoint (and the echo fixture), and is
  the only extra anchor handed to Certbot through ``REQUESTS_CA_BUNDLE``;
* Pebble signs the certificates it issues with its own internal root, which the
  clients receive from the management API (``/roots/0``) — never from a global
  trust store;
* nothing here writes to ``/usr/local/share/ca-certificates`` or updates the
  system bundle.

The endpoint is a constant, not user input: ``modules/nginx.sh`` accepts exactly
this URL in test mode, so a case cannot point the installer at an arbitrary ACME
server by setting an environment variable.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Sequence

from .podman import wait_until

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ACME_TEMPLATE_DIR = REPO_ROOT / "tests" / "fixtures" / "acme"
PEBBLE_CONFIG_TEMPLATE = ACME_TEMPLATE_DIR / "pebble-config.json"

FIXTURE_HOST = "pebble.testbed.internal"
ACME_PORT = 14000
MANAGEMENT_PORT = 15000
# Pebble connects to these ports on the target during validation, so they must
# match a public CA's: the product's HTTP-01 path is port 80 and TLS-ALPN-01 is
# 443. The fixture binds neither port itself; only its management API is
# published, on loopback.
CHALLENGE_HTTP_PORT = 80
CHALLENGE_TLS_PORT = 443

CONTAINER_FIXTURE_DIR = "/fixtures/acme"

# Pebble rejects a percentage of requests with ``badNonce`` by default (5%) so
# that ACME client retry logic can be exercised. That is a feature of Pebble's
# own test suite, not of the product under test: here it would turn one install
# in twenty into a failure that says nothing about GoWave. The knob is set to
# zero so a certificate request either works or does not, deterministically.
FIXTURE_ENVIRONMENT = {"PEBBLE_WFE_NONCEREJECT": "0"}

# Must stay byte-identical to GOWAVE_ACME_TEST_ENDPOINT in modules/nginx.sh and
# gowave-node-auto.sh; a divergence would make test mode unreachable rather than
# silently insecure, and the consistency test fails on drift.
ACME_DIRECTORY_URL = f"https://{FIXTURE_HOST}:{ACME_PORT}/dir"

FIXTURE_CA_COMMON_NAME = "GoWave Podman Fixture CA"


class AcmeFixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class FixtureCA:
    directory: Path
    root_cert: Path
    root_key: Path

    @property
    def root_pem(self) -> str:
        return self.root_cert.read_text(encoding="utf-8")


def _openssl(argv: Sequence[str], timeout: int = 60) -> None:
    proc = subprocess.run(
        ["openssl", *argv], capture_output=True, text=True, check=False, timeout=timeout,
    )
    if proc.returncode != 0:
        raise AcmeFixtureError(f"openssl {' '.join(argv)} failed: {proc.stderr.strip() or proc.stdout.strip()}")


def _san_extensions(sans: Sequence[str]) -> str:
    # OpenSSL 3.5 rejects a leaf whose issuer key id is not resolvable
    # ("Missing Authority Key Identifier"), so both ids are always emitted.
    return (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n"
        f"subjectAltName={','.join(sans)}\n"
    )


def generate_fixture_ca(
    directory: Path,
    sans: Sequence[str] = ("DNS:pebble.testbed.internal", "DNS:localhost", "IP:127.0.0.1"),
    days: int = 30,
) -> FixtureCA:
    """Create the fixture root CA and the Pebble TLS leaf it signs."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_key = directory / "fixture-root.key"
    root_cert = directory / "fixture-root.crt"
    pebble_key = directory / "pebble.key"
    pebble_csr = directory / "pebble.csr"
    pebble_cert = directory / "pebble.crt"
    ext_file = directory / "pebble.ext"

    _openssl([
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(root_key), "-out", str(root_cert), "-days", str(days),
        "-subj", f"/CN={FIXTURE_CA_COMMON_NAME}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ])
    _openssl([
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(pebble_key), "-out", str(pebble_csr),
        "-subj", f"/CN={FIXTURE_HOST}",
    ])
    ext_file.write_text(_san_extensions(sans), encoding="utf-8")
    _openssl([
        "x509", "-req", "-in", str(pebble_csr),
        "-CA", str(root_cert), "-CAkey", str(root_key), "-CAcreateserial",
        "-out", str(pebble_cert), "-days", str(days),
        "-extfile", str(ext_file),
    ])
    for path in (root_key, pebble_key):
        path.chmod(0o600)
    return FixtureCA(directory=directory, root_cert=root_cert, root_key=root_key)


def generate_leaf(directory: Path, name: str, sans: Sequence[str]) -> Dict[str, Path]:
    """Issue an additional leaf from the fixture CA (e.g. the echo HTTPS listener)."""
    directory = Path(directory)
    root_cert = directory / "fixture-root.crt"
    root_key = directory / "fixture-root.key"
    if not root_cert.exists() or not root_key.exists():
        raise AcmeFixtureError("generate_fixture_ca must run before issuing leaves")
    key = directory / f"{name}.key"
    csr = directory / f"{name}.csr"
    cert = directory / f"{name}.crt"
    ext_file = directory / f"{name}.ext"
    _openssl([
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={sans[0].removeprefix('DNS:')}",
    ])
    ext_file.write_text(_san_extensions(sans), encoding="utf-8")
    _openssl([
        "x509", "-req", "-in", str(csr),
        "-CA", str(root_cert), "-CAkey", str(root_key), "-CAcreateserial",
        "-out", str(cert), "-days", "30", "-extfile", str(ext_file),
    ])
    key.chmod(0o600)
    return {"cert": cert, "key": key}


def pebble_config() -> Dict[str, object]:
    if not PEBBLE_CONFIG_TEMPLATE.exists():
        raise AcmeFixtureError(f"{PEBBLE_CONFIG_TEMPLATE.relative_to(REPO_ROOT)} is missing")
    data = json.loads(PEBBLE_CONFIG_TEMPLATE.read_text(encoding="utf-8"))
    pebble = data.get("pebble") or {}
    required = {
        "listenAddress": f"0.0.0.0:{ACME_PORT}",
        "managementListenAddress": f"0.0.0.0:{MANAGEMENT_PORT}",
        "certificate": f"{CONTAINER_FIXTURE_DIR}/pebble.crt",
        "privateKey": f"{CONTAINER_FIXTURE_DIR}/pebble.key",
    }
    for key, expected in required.items():
        if pebble.get(key) != expected:
            raise AcmeFixtureError(f"pebble config {key} must be {expected!r}, found {pebble.get(key)!r}")
    if pebble.get("externalAccountBindingRequired") is not False:
        raise AcmeFixtureError("pebble config must not require external account binding")
    return data


def prepare_acme_directory(directory: Path) -> FixtureCA:
    """Materialize the config, CA, and Pebble TLS leaf in a private directory."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    pebble_config()
    ca = generate_fixture_ca(directory)
    shutil.copyfile(PEBBLE_CONFIG_TEMPLATE, directory / "pebble-config.json")
    (directory / "pebble-config.json").chmod(0o600)
    return ca


def ca_file_sha256(ca_file: Path) -> str:
    """Hex SHA-256 of the CA file bytes, exactly what GOWAVE_ACME_TEST_CA_SHA256 expects."""
    return hashlib.sha256(Path(ca_file).read_bytes()).hexdigest()


def ca_der_digest(ca_file: Path) -> str:
    """SHA-256 of the DER CA certificate, for evidence and cross-run pinning."""
    with tempfile.NamedTemporaryFile(suffix=".der") as handle:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(ca_file), "-outform", "DER", "-out", handle.name],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if proc.returncode != 0:
            raise AcmeFixtureError(f"could not DER-encode {ca_file}: {proc.stderr.strip()}")
        return "sha256:" + hashlib.sha256(Path(handle.name).read_bytes()).hexdigest()


def fetch_issued_root(
    host: str = FIXTURE_HOST,
    ca_file: Optional[Path] = None,
    timeout: int = 30,
    port: int = MANAGEMENT_PORT,
) -> str:
    """Fetch Pebble's issuing root over the CA-trusted management endpoint."""
    url = f"https://{host}:{port}/roots/0"
    context = ssl.create_default_context(cafile=str(ca_file)) if ca_file is not None else ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=context) as response:
            pem = response.read().decode("utf-8")
    except (OSError, urllib.error.URLError) as exc:
        raise AcmeFixtureError(f"could not fetch the Pebble issuing root from {url}: {exc}") from exc
    if "BEGIN CERTIFICATE" not in pem:
        raise AcmeFixtureError(f"{url} did not return a PEM certificate")
    return pem


def trust_environment(ca_file: Path) -> Dict[str, str]:
    """Scoped CA trust for tooling that honours the requests/OpenSSL bundle."""
    return {
        "REQUESTS_CA_BUNDLE": str(ca_file),
        "SSL_CERT_FILE": str(ca_file),
        "CURL_CA_BUNDLE": str(ca_file),
    }


class AcmeFixture:
    """Pebble started as a run-scoped container beside the topology."""

    def __init__(
        self,
        podman,
        network: str,
        directory: Optional[Path] = None,
        host_alias: str = FIXTURE_HOST,
        extra_args: Sequence[str] = (),
        management_host_port: Optional[int] = None,
    ) -> None:
        self.podman = podman
        self.context = podman.context
        self.network = network
        self.name = self.context.resource_name("acme-pebble")
        self.directory = Path(directory) if directory else self.context.secret_dir / "acme"
        self.host_alias = host_alias
        self.extra_args = tuple(extra_args)
        # The harness runs outside the topology network, so the management API is
        # published on loopback and reached by the leaf's IP SAN.
        self.management_host_port = management_host_port
        self.ca: Optional[FixtureCA] = None
        self._root_pem: Optional[str] = None

    def start(self) -> "AcmeFixture":
        self.ca = prepare_acme_directory(self.directory)
        self.podman.run(
            name=self.name,
            image_alias="acme-pebble",
            network=self.network,
            aliases=(self.host_alias,),
            privileged=False,
            volumes=(f"{self.directory}:{CONTAINER_FIXTURE_DIR}:ro,Z",),
            environment=dict(FIXTURE_ENVIRONMENT),
            command=("-config", f"{CONTAINER_FIXTURE_DIR}/pebble-config.json"),
            systemd="false",
            extra_args=self._podman_args(),
        )
        self.context.add_cleanup(self.stop)
        return self

    def _podman_args(self) -> Sequence[str]:
        args = list(self.extra_args)
        if self.management_host_port:
            args += ["-p", f"127.0.0.1:{self.management_host_port}:{MANAGEMENT_PORT}"]
        return tuple(args)

    def wait_ready(self, timeout_seconds: int = 120) -> None:
        """Readiness is observed from outside: the pinned Pebble image has no shell.

        Executing a probe inside the container would need ``bash`` or ``sh``,
        which the image does not ship, so a published management port is polled
        over loopback TLS with the fixture CA pinned; that also proves the
        directory is serving trusted TLS before the operator runs.
        """
        if self.management_host_port:
            if not wait_until(self._management_root, timeout_seconds, f"Pebble fixture {self.name}"):
                raise AcmeFixtureError(
                    f"Pebble management API on 127.0.0.1:{self.management_host_port} did not become ready "
                    f"within {timeout_seconds}s"
                )
            return
        self.podman.wait_tcp(self.name, self.host_alias, ACME_PORT, timeout_seconds=timeout_seconds)

    def _management_root(self) -> bool:
        try:
            self._root_pem = fetch_issued_root(
                "127.0.0.1", self.ca_file(), timeout=5, port=self.management_host_port,
            )
        except AcmeFixtureError:
            return False
        return True

    def directory_url(self) -> str:
        return ACME_DIRECTORY_URL

    def ca_file(self) -> Path:
        if self.ca is None:
            raise AcmeFixtureError("the fixture CA has not been generated")
        return self.ca.root_cert

    def issued_root(self) -> str:
        if self._root_pem is None:
            if self.management_host_port:
                self._root_pem = fetch_issued_root("127.0.0.1", self.ca_file(), port=self.management_host_port)
            else:
                self._root_pem = fetch_issued_root(self.host_alias, self.ca_file())
        return self._root_pem

    def stop(self) -> None:
        self.podman._run(["rm", "-f", self.name], check=False)

    def evidence(self) -> Dict[str, object]:
        ca_file = self.ca_file() if self.ca else None
        return {
            "endpoint": ACME_DIRECTORY_URL,
            "container": self.name,
            "ca_file": str(ca_file) if ca_file else "",
            "ca_file_sha256": ca_file_sha256(ca_file) if ca_file else "",
            "ca_der_digest": ca_der_digest(ca_file) if ca_file else "",
        }
