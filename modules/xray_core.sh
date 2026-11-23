#!/usr/bin/env bash
# modules/xray_core.sh - The pinned Xray core a node installation places before
# the upstream installer runs.
#
# Upstream install.sh spends an api.github.com request buying a core whenever it
# finds no executable rw-core. Placing a digest-verified release there first is
# what removes that request, so the pin is a table of published bytes rather than
# a version string: each row names the archive and the SHA-256 the download is
# checked against.set -Eeuo pipefail

_GOWAVE_XRAY_CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Sourced so this module can be exercised on its own; every module tolerates a
# second sourcing.
source "$_GOWAVE_XRAY_CORE_DIR/os.sh"
source "$_GOWAVE_XRAY_CORE_DIR/tempdir.sh"
source "$_GOWAVE_XRAY_CORE_DIR/artifact.sh"

GOWAVE_PINNED_XRAY_VERSION="26.11.9"
GOWAVE_PINNED_XRAY_AMD64_URL="https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip"
GOWAVE_PINNED_XRAY_AMD64_SHA256="b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"
GOWAVE_PINNED_XRAY_ARM64_URL="https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm64-v8a.zip"
GOWAVE_PINNED_XRAY_ARM64_SHA256="64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be"

# pinned_xray_artifact VERSION ARCH - print "<url> <sha256>" for a row of the
# table. The rows are plain variables read here rather than from the
# environment, so a unit test can point one at an archive it built itself.
pinned_xray_artifact() {
    local version="${1#v}"
    local arch="$2"

    [[ "$version" == "$GOWAVE_PINNED_XRAY_VERSION" ]] || return 1
    case "$arch" in
        amd64) printf '%s %s\n' "$GOWAVE_PINNED_XRAY_AMD64_URL" "$GOWAVE_PINNED_XRAY_AMD64_SHA256" ;;
        arm64) printf '%s %s\n' "$GOWAVE_PINNED_XRAY_ARM64_URL" "$GOWAVE_PINNED_XRAY_ARM64_SHA256" ;;
        *) return 1 ;;
    esac
}

# pinned_xray_arch - the lookup key for the table. The mapping itself lives in
# os.sh, so the architecture is not decided a second time here.
pinned_xray_arch() {
    detect_arch
}

core_version_matches() {
    local reported="${1:-}"
    local expected="${2:-}"
    [[ -n "$expected" ]] || return 1
    local token
    for token in $reported; do
        if [[ "$token" == "$expected" ]]; then
            return 0
        fi
    done
    return 1
}

# pinned_xray_fail REASON [ARTIFACT] - the one place a failure on this path is
# reported, so each condition prints one located message. The opt-out is named
# in words an operator can copy. A condition without an artifact (an
# unsupported architecture) names no URL, because the table has none for it.
pinned_xray_fail() {
    local reason="$1"
    local artifact="${2:-}"
    local subject="pinned Xray core $GOWAVE_PINNED_XRAY_VERSION"
    local opt_out="Set XRAY_SERVER_VERSION=latest to let the upstream installer fetch a core instead."

    if [[ -n "$artifact" ]]; then
        printf 'Error: %s could not be installed from %s: %s. %s\n' \
            "$subject" "$artifact" "$reason" "$opt_out" >&2
    else
        printf 'Error: %s could not be installed: %s. %s\n' \
            "$subject" "$reason" "$opt_out" >&2
    fi
    return 1
}

# pinned_xray_deliver SCRATCH INSTALL_DIR URL DIGEST - fetch, verify, unpack and
# install one archive. Returns non-zero after reporting the condition that
# stopped it; the caller owns SCRATCH.
pinned_xray_deliver() {
    local scratch="$1"
    local install_dir="$2"
    local url="$3"
    local digest="$4"
    local zip="$scratch/Xray.zip"
    local member="$scratch/xray"
    local reported=""
    local fetch_rc=0

    fetch_verified_artifact "$zip" "Xray core $GOWAVE_PINNED_XRAY_VERSION" "$url" "$digest" || fetch_rc=$?
    if (( fetch_rc == 2 )); then
        pinned_xray_fail "the archive did not match the pinned SHA-256" "$url"
        return 1
    elif (( fetch_rc != 0 )); then
        pinned_xray_fail "no artifact host delivered the archive" "$url"
        return 1
    fi

    if ! python3 - "$zip" "$member" <<'PY'
import sys
import zipfile

archive, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as bundle, bundle.open("xray") as src, open(dest, "wb") as out:
    out.write(src.read())
PY
    then
        pinned_xray_fail "the archive carries no readable xray member" "$url"
        return 1
    fi

    chmod 0755 "$member"
    reported=$("$member" version 2>/dev/null || true)
    if ! core_version_matches "$reported" "$GOWAVE_PINNED_XRAY_VERSION"; then
        pinned_xray_fail "the extracted core reports ${reported:-nothing}, not $GOWAVE_PINNED_XRAY_VERSION" "$url"
        return 1
    fi

    mkdir -p "$install_dir"
    local staged="$install_dir/.rw-core.pinned.$$"
    rm -f -- "$staged"
    if ! install -m 0755 -- "$member" "$staged"; then
        pinned_xray_fail "the verified core could not be staged in $install_dir" "$url"
        return 1
    fi
    sync "$staged" 2>/dev/null || true
    if ! mv -f -- "$staged" "$install_dir/rw-core"; then
        rm -f -- "$staged" || true
        pinned_xray_fail "the verified core could not be installed at $install_dir/rw-core" "$url"
        return 1
    fi
    sync "$install_dir" 2>/dev/null || true

    printf 'Installed pinned Xray core %s from %s (SHA-256 %s).\n' \
        "$GOWAVE_PINNED_XRAY_VERSION" "$url" "$digest"
}

# install_pinned_xray_core INSTALL_DIR - place the pinned core so the upstream
# installer finds an executable rw-core and provisions none of its own.
#
# XRAY_SERVER_VERSION has exactly one meaning per value: unset, or naming the
# pin itself, installs the pin; "latest" is the explicit opt-out; any other
# version belongs to upstream and the explicit-version path.
install_pinned_xray_core() {
    local install_dir="${1:?an install directory is required}"
    local requested="${XRAY_SERVER_VERSION:-}"
    local version="${requested,,}"

    if [[ -n "$version" ]]; then
        version="${version#v}"
        [[ "$version" == "$GOWAVE_PINNED_XRAY_VERSION" ]] || return 0
    fi

    local arch="" artifact=""
    if ! arch=$(pinned_xray_arch 2>&1); then
        pinned_xray_fail "$arch"
        return 1
    fi
    if ! artifact=$(pinned_xray_artifact "$GOWAVE_PINNED_XRAY_VERSION" "$arch"); then
        pinned_xray_fail "no artifact is pinned for architecture $arch"
        return 1
    fi

    local url="${artifact% *}"
    local digest="${artifact##* }"
    local dest="$install_dir/rw-core"

    if [[ -x "$dest" ]]; then
        local reported
        reported=$("$dest" version 2>/dev/null || true)
        if core_version_matches "$reported" "$GOWAVE_PINNED_XRAY_VERSION"; then
            return 0
        fi
    fi

    local scratch rc=0
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/gowave-xray-core-XXXXXX")
    track_temp_dir "$scratch"
    pinned_xray_deliver "$scratch" "$install_dir" "$url" "$digest" || rc=$?
    release_temp_dir "$scratch"
    return "$rc"
}
