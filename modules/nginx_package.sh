#!/usr/bin/env bash
set -Eeuo pipefail

install_pinned_nginx() (
    # The Worker payload runs with umask 077; APT verifies Signed-By as _apt, so
    # the public key, the source list and the index must be world-readable.
    umask 022
    local distro="$1" codename="$2"
    local fingerprint=8540A6F18833A80E9C1653A42FD21310B49F6B46
    local arch version installed scratch apt_uri config available
    local nginx_bin="${NGINX_BINARY:-/usr/sbin/nginx}"
    local apt_options=()
    case "$distro:$codename" in
        debian:bookworm|debian:trixie|ubuntu:noble|ubuntu:resolute) ;;
        *) echo "Error: No approved NGINX repository for $distro/$codename." >&2; return 1 ;;
    esac
    arch=$(dpkg --print-architecture) || return 1
    case "$arch" in
        amd64|arm64) ;;
        *) echo "Error: No approved NGINX package for $codename/$arch." >&2; return 1 ;;
    esac
    version="1.30.8-1~${codename}"
    installed=$(dpkg-query -W -f='${Version}' nginx 2>/dev/null) || installed=""
    if [[ -n "$installed" ]] && dpkg --compare-versions "$installed" gt "$version"; then
        echo "Error: Refusing to downgrade installed NGINX $installed to $version." >&2
        return 1
    fi

    scratch=$(mktemp -d) || return 1
    # The body is one subshell, so this EXIT trap fires on every return path and
    # keeps the module usable in the Worker payload, which ships without
    # modules/tempdir.sh.
    trap 'rm -rf -- "$scratch"' EXIT
    # APT's sandbox must be able to traverse the workspace to read Signed-By.
    chmod 0755 "$scratch" || return 1
    mkdir -m 0700 "$scratch/gnupg" || return 1
    mkdir -m 0755 "$scratch/lists" || return 1
    curl --proto '=https' --fail --silent --show-error --location --max-time 60 \
        --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 15 \
        https://nginx.org/keys/nginx_signing.key -o "$scratch/vendor.asc" || return 1
    gpg --batch --homedir "$scratch/gnupg" --import "$scratch/vendor.asc" || return 1
    gpg --batch --homedir "$scratch/gnupg" --export "$fingerprint" > "$scratch/vendor.gpg" || return 1
    [[ -s "$scratch/vendor.gpg" ]] || { echo 'Error: Approved NGINX signing key not found.' >&2; return 1; }
    chmod 0644 "$scratch/vendor.gpg" || return 1

    apt_uri="https://nginx.org/packages/${distro}/"
    printf 'deb [arch=%s signed-by=%s] %s %s nginx\n' \
        "$arch" "$scratch/vendor.gpg" "$apt_uri" "$codename" > "$scratch/vendor.list" || return 1
    # A re-apply over a serving Worker must not fail on one dropped connection to
    # the vendor: the refresh, the download and the install are the same
    # authenticated fetch, so the retry budget belongs to all of them. Exhausting
    # it is still a refusal, and still no distribution fallback.
    apt_options=(-o "Dir::Etc::sourcelist=$scratch/vendor.list" -o Dir::Etc::sourceparts=-
                 -o "Dir::State::lists=$scratch/lists" -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=
                 -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false
                 -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
    apt-get "${apt_options[@]}" -o APT::Update::Error-Mode=any update -qq </dev/null || {
        echo "Error: Could not authenticate or refresh the official NGINX repository for $codename." >&2
        return 1
    }
    available=$(apt-cache "${apt_options[@]}" madison nginx) || {
        echo "Error: Could not read the authenticated NGINX package index for $codename." >&2
        return 1
    }
    if ! awk -F'|' -v version="$version" -v uri="${apt_uri%/}" '
        { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); if ($2 == version && index($3, uri)) found=1 }
        END { exit !found }
    ' <<< "$available"; then
        # The currently tracked distro revisions do not have a confirmed fix for CVE-2026-132779.
        echo "Error: Official NGINX $version is unavailable and no distribution fallback is approved." >&2
        return 1
    fi
    (
        cd "$scratch" && apt-get "${apt_options[@]}" download "nginx:${arch}=${version}" </dev/null
    ) || return 1
    local packages=("$scratch"/nginx_*.deb)
    [[ "${#packages[@]}" -eq 1 && -f "${packages[0]}" ]] || return 1
    if [[ "$(dpkg-deb -f "${packages[0]}" Package)" != nginx ||
          "$(dpkg-deb -f "${packages[0]}" Version)" != "$version" ||
          "$(dpkg-deb -f "${packages[0]}" Architecture)" != "$arch" ]]; then
        echo "Error: Downloaded NGINX package does not match the approved identity: $version/$arch." >&2
        return 1
    fi

    if [[ "$installed" != "$version" ]] ||
        ! (dpkg-deb --fsys-tarfile "${packages[0]}" | tar -xOf - ./usr/sbin/nginx | cmp -s - /usr/sbin/nginx); then
        # `--no-remove` cannot be used here: the official `nginx` Conflicts with
        # and Replaces `nginx-common`/`nginx-core`, so removing the distribution
        # packages is the install, not an unwanted side effect.
        DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends \
            -o Dpkg::Options::=--force-confold install --reinstall "${packages[0]}" </dev/null || return 1
    fi
    if [[ "$(dpkg-query -W -f='${Status} ${Version}' nginx 2>/dev/null)" != "install ok installed $version" ]] ||
        ! dpkg-deb --fsys-tarfile "${packages[0]}" | tar -xOf - ./usr/sbin/nginx | cmp -s - /usr/sbin/nginx; then
        echo "Error: Installed NGINX does not match the authenticated package $version." >&2
        return 1
    fi
    config="$("$nginx_bin" -V 2>&1)" || return 1
    if [[ " $config " != *' --with-stream '* || " $config " != *' --with-stream_ssl_preread_module '* ]]; then
        echo "Error: NGINX $version lacks the required static Stream SNI support." >&2
        return 1
    fi
    printf 'Verified official NGINX %s (%s, Stream SNI).\n' "$version" "$arch"
)
