#!/usr/bin/env bash
# modules/artifact.sh - Pinned-artifact delivery for hosts that publish the same
# bytes more than once.
#
# A release is served from GitHub and from a mirror that both name a commit, and
# a pinned artifact is only as trustworthy as the bytes that reach the disk. The
# single helper here owns that decision for every caller, so the Panel release
# assets and the Node installer cannot drift apart in how they verify.
set -Eeuo pipefail

# fetch_verified_artifact DEST NAME URL [URL...] DIGEST
#
# Tries each host in order and installs the bytes only after they match DIGEST.
# A host that cannot deliver is a transport fault and the next host is tried; a
# host that delivers different bytes is terminal, because a pinned artifact that
# answers differently from a second source is a supply-chain signal, not a
# network problem. Returns 2 on a digest mismatch, 1 when no host delivered.
fetch_verified_artifact() {
    local dest="$1"
    local name="$2"
    local digest="${!#}"
    local -a urls=("${@:3:$#-3}")

    if [[ ! "$digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "Error: $name needs a 64-character SHA-256 digest to be verified against." >&2
        return 2
    fi
    if [[ ${#urls[@]} -eq 0 ]]; then
        echo "Error: $name has no source host to be fetched from." >&2
        return 1
    fi
    digest="${digest,,}"

    local tmp="${dest}.part.$$"
    local url actual
    for url in "${urls[@]}"; do
        rm -f -- "$tmp"
        if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 120 "$url" -o "$tmp" 2>/dev/null ||
            [[ ! -s "$tmp" ]]; then
            echo "Warning: $name was not delivered by $url." >&2
            continue
        fi
        actual=$(sha256sum -- "$tmp" | awk '{print $1}')
        if [[ "$actual" != "$digest" ]]; then
            rm -f -- "$tmp"
            echo "Error: $name SHA256 mismatch: expected $digest, got $actual (source $url)." >&2
            echo "Refusing a pinned artifact that a host answered differently; no further host is tried." >&2
            return 2
        fi
        if ! sync "$tmp" 2>/dev/null; then
            rm -f -- "$tmp"
            echo "Error: could not flush the verified download of $name to disk." >&2
            return 1
        fi
        if ! mv -f -- "$tmp" "$dest"; then
            rm -f -- "$tmp"
            echo "Error: could not install the verified download of $name at $dest." >&2
            return 1
        fi
        sync "$(dirname -- "$dest")" 2>/dev/null || true
        return 0
    done
    rm -f -- "$tmp"
    echo "Error: no source could deliver $name." >&2
    return 1
}
