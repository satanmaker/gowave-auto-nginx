"""Clean supported target images for the All-in-One product E2E.

The image deliberately contains only a working service manager and package
manager. Every package the product needs is installed by the operator under
test, so a missing prerequisite step fails the case instead of being masked by
the test image.

Base images are pinned by registry digest through ``images.build``; the
resolved digest is part of the evidence and never a mutable tag.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTAINERFILE = REPO_ROOT / "tests" / "Containerfile.target"

TAG_PREFIX = "gowave-e2e-target"

DISTRIBUTIONS = {
    "ubuntu-24.04": "ubuntu",
    "ubuntu-26.04": "ubuntu",
    "debian-12": "debian",
    "debian-13": "debian",
}

# Exactly the packages the operator is responsible for installing. None of them
# may be baked into the image, which is what makes the install path observable.
# gzip is omitted on purpose: it ships in every supported base image, so its
# presence says nothing about what the operator did.
PRODUCT_PACKAGES = (
    "nginx-full",
    "libnginx-mod-stream",
    "certbot",
    "python3-systemd",
    "sqlite3",
    "openssl",
    "ufw",
    "fail2ban",
    "systemd-resolved",
    "iproute2",
    "ca-certificates",
    "openssh-client",
    "openssh-server",
    "sudo",
)


class TargetImageError(RuntimeError):
    pass


def distribution(alias: str) -> str:
    try:
        return DISTRIBUTIONS[alias]
    except KeyError as exc:
        raise TargetImageError(f"unsupported target distribution: {alias!r}") from exc


def tag(alias: str) -> str:
    distribution(alias)
    return f"{TAG_PREFIX}:{alias}"


def containerfile() -> str:
    """The target Containerfile, validated against the cleanliness contract."""
    if not CONTAINERFILE.is_file():
        raise TargetImageError(f"{CONTAINERFILE.relative_to(REPO_ROOT)} is missing")
    text = CONTAINERFILE.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if "ARG BASE_IMAGE=docker.io/library/" not in code:
        raise TargetImageError("the target image must declare a pinned BASE_IMAGE build argument")
    if "FROM ${BASE_IMAGE}" not in code:
        raise TargetImageError("the target image must build from ${BASE_IMAGE}")
    if 'CMD ["/sbin/init"]' not in code:
        raise TargetImageError("the target image must boot systemd as PID 1")
    if "STOPSIGNAL SIGRTMIN+3" not in code:
        raise TargetImageError("the target image must stop systemd with SIGRTMIN+3")
    if "ENV container=podman" not in code:
        raise TargetImageError("the target image must declare the Podman container environment")
    baked = [package for package in PRODUCT_PACKAGES if re.search(rf"(?<![\w-]){re.escape(package)}(?![\w-])", code)]
    if baked:
        raise TargetImageError(
            "the target image must stay clean; the operator installs: " + ", ".join(baked)
        )
    return text


def build(podman, alias: str, context_dir: Optional[Path] = None) -> str:
    """Build the clean target image from the digest-pinned base."""
    containerfile()
    image_tag = tag(alias)
    podman.build(
        tag=image_tag,
        base_alias=alias,
        containerfile=CONTAINERFILE,
        context_dir=Path(context_dir) if context_dir else CONTAINERFILE.parent,
    )
    return image_tag


def cleanliness_probe() -> str:
    """Shell probe that reports what the image contains before the operator runs."""
    package_list = " ".join(PRODUCT_PACKAGES)
    return (
        'printf "init=%s\\n" "$(ps -p 1 -o comm= 2>/dev/null || true)"; '
        'printf "systemd=%s\\n" "$(systemctl --version 2>/dev/null | head -n1 || true)"; '
        'for pkg in ' + package_list + '; do '
        'if dpkg-query -W -f=\'${Status}\' "$pkg" 2>/dev/null | grep -q "install ok installed"; then '
        'printf "installed=%s\\n" "$pkg"; fi; done'
    )


def parse_probe(output: str) -> Dict[str, Any]:
    init = ""
    systemd = ""
    installed = []
    for line in output.splitlines():
        key, _, value = line.partition("=")
        if key == "init":
            init = value.strip()
        elif key == "systemd":
            systemd = value.strip()
        elif key == "installed":
            installed.append(value.strip())
    return {"init": init, "systemd": systemd, "installed": sorted(item for item in installed if item)}


def assert_clean(podman, container: str) -> Dict[str, Any]:
    """Prove the target is a clean systemd host before the operator touches it."""
    result = podman.exec(container, ["bash", "-lc", cleanliness_probe()])
    facts = parse_probe(result.stdout)
    if facts["init"] != "systemd":
        raise TargetImageError(f"{container} is not running systemd as PID 1 (found {facts['init']!r})")
    if not facts["systemd"].startswith("systemd"):
        raise TargetImageError(f"{container} has no usable systemctl: {facts['systemd']!r}")
    if facts["installed"]:
        raise TargetImageError(
            f"{container} already contains product packages: {', '.join(facts['installed'])}"
        )
    return facts


def evidence(alias: str, container: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "distribution": distribution(alias),
        "distribution_alias": alias,
        "image_tag": tag(alias),
        "container": container,
        "pid1": facts.get("init", ""),
        "systemd": facts.get("systemd", ""),
        "preinstalled_product_packages": facts.get("installed", []),
    }
