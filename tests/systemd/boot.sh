#!/usr/bin/env bash
# tests/systemd/boot.sh - Real systemd guest runner using QEMU for GoWave Auto NGINX
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

SUPPORTED_DISTROS=(
    "docker.io/library/ubuntu:24.04"
    "docker.io/library/ubuntu:26.04"
    "docker.io/library/debian:12"
    "docker.io/library/debian:13"
)

boot_single_distro() {
    local target_distro="$1"
    local work_dir="${2:-}"
    local clean_work_dir=0

    if [[ -z "$work_dir" ]]; then
        work_dir=$(mktemp -d /tmp/gowave-qemu-XXXXXX)
        clean_work_dir=1
    fi

    echo "================================================================================"
    echo "QEMU Cold Boot Acceptance: $target_distro"
    echo "Work directory: $work_dir"
    echo "Repo directory: $REPO_DIR"
    echo "================================================================================"

    mkdir -p "$work_dir"

    # If rootfs.tar is not provided, build it automatically from Containerfile.testbed
    if [[ ! -s "$work_dir/rootfs.tar" ]]; then
        echo "Building rootfs for $target_distro using Containerfile.testbed..."
        local builder=""
        if command -v docker >/dev/null 2>&1; then
            builder="docker"
        elif command -v podman >/dev/null 2>&1; then
            builder="podman"
        else
            echo "ERROR: Neither docker nor podman is available to build rootfs for $target_distro." >&2
            echo "Provide a prepared $work_dir/rootfs.tar or install docker/podman." >&2
            exit 2
        fi

        local img_tag="gowave-boot-$(basename "${target_distro//:/-}"):$$"
        "$builder" build -t "$img_tag" -f "${REPO_DIR}/tests/Containerfile.testbed" --build-arg "BASE_IMAGE=$target_distro" "${REPO_DIR}/tests"
        local cid
        cid=$("$builder" create "$img_tag")
        "$builder" export "$cid" -o "${work_dir}/rootfs.tar"
        "$builder" rm "$cid" >/dev/null
        "$builder" rmi "$img_tag" >/dev/null 2>&1 || true
    fi

    [[ -s "$work_dir/rootfs.tar" ]] || { echo "ERROR: $work_dir/rootfs.tar is missing or empty." >&2; exit 2; }
    command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "ERROR: qemu-system-x86_64 is required." >&2; exit 2; }
    command -v cpio >/dev/null 2>&1 || { echo "ERROR: cpio is required." >&2; exit 2; }
    command -v gzip >/dev/null 2>&1 || { echo "ERROR: gzip is required." >&2; exit 2; }
    command -v timeout >/dev/null 2>&1 || { echo "ERROR: timeout is required." >&2; exit 2; }
    [[ -d "$REPO_DIR" ]] || { echo "ERROR: REPO_DIR does not exist: $REPO_DIR" >&2; exit 2; }

    rm -f "${work_dir}/reboot-policy.tar" "${work_dir}/pre-boot-id" "${work_dir}/reboot.cpio.gz"
    rm -rf "${work_dir}/root"
    mkdir -p "${work_dir}/root"

    echo "Extracting rootfs.tar..."
    tar -xf "${work_dir}/rootfs.tar" -C "${work_dir}/root"
    if [[ ! -x "${work_dir}/root/sbin/init" && ! -x "${work_dir}/root/usr/lib/systemd/systemd" && ! -x "${work_dir}/root/lib/systemd/systemd" ]]; then
        echo "ERROR: rootfs does not contain executable /sbin/init or systemd binary." >&2
        exit 2
    fi

    if [[ -d /lib/modules ]]; then
        mkdir -p "${work_dir}/root/usr/lib"
        cp -a /lib/modules "${work_dir}/root/usr/lib/"
    fi

    mkdir -p "${work_dir}/root/repo"
    cp -a "${REPO_DIR}/." "${work_dir}/root/repo/"

    rm -f "${work_dir}/root/.dockerenv" "${work_dir}/root/etc/machine-id"

    # Configure DNS resolution in rootfs
    mkdir -p "${work_dir}/root/etc/systemd"
    printf '[Resolve]\nDNS=8.8.8.8 1.1.1.1\n' > "${work_dir}/root/etc/systemd/resolved.conf"
    chmod 0644 "${work_dir}/root/etc/systemd/resolved.conf"

    mkdir -p "${work_dir}/root/dev" "${work_dir}/root/proc" "${work_dir}/root/sys" "${work_dir}/root/run"

    cat > "${work_dir}/root/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
if [ -x /sbin/init ]; then
    exec /sbin/init
elif [ -x /lib/systemd/systemd ]; then
    exec /lib/systemd/systemd
elif [ -x /usr/lib/systemd/systemd ]; then
    exec /usr/lib/systemd/systemd
else
    echo "Fatal: No init found in rootfs" >&2
    exit 1
fi
INIT
    chmod 0755 "${work_dir}/root/init"

    cat > "${work_dir}/root/etc/systemd/system/gowave-ci.service" <<'UNIT'
[Unit]
Description=GoWave Auto NGINX CI Systemd Cold Boot Runner
After=systemd-journald.service dbus.service

[Service]
Type=oneshot
WorkingDirectory=/repo
ExecStart=/bin/bash -c 'python3 tests/run_ci.py --suite systemd; rc=$?; if [ "$rc" = 0 ]; then echo GOWAVE_SYSTEMD_TEST_PASS; else echo GOWAVE_SYSTEMD_TEST_FAIL; fi; systemctl poweroff; exit "$rc"'
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
UNIT

    mkdir -p "${work_dir}/root/etc/systemd/system/multi-user.target.wants"
    ln -sf ../gowave-ci.service "${work_dir}/root/etc/systemd/system/multi-user.target.wants/gowave-ci.service"

    echo "Building initramfs cpio archive..."
    (
        cd "${work_dir}/root"
        find . -xdev -print0 | cpio --null -o --format=newc 2>"${work_dir}/cpio.log" | gzip -1 > "${work_dir}/rootfs.cpio.gz"
    )

    local kernel
    kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -type f 2>/dev/null | sort -V | tail -1)
    [[ -n "$kernel" ]] || { echo "ERROR: host kernel image not found under /boot." >&2; exit 2; }

    local accel_args=(-machine accel=tcg)
    if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
        accel_args=(-enable-kvm -cpu host)
    fi

    echo "Booting QEMU guest with kernel $kernel (accel: ${accel_args[*]})..."
    timeout 15m qemu-system-x86_64 "${accel_args[@]}" -m 2048 -smp 2 -nodefaults \
        -no-reboot -display none -serial stdio -monitor none -nic none \
        -kernel "$kernel" -initrd "${work_dir}/rootfs.cpio.gz" \
        -append 'console=ttyS0 panic=1 quiet rdinit=/init systemd.show_status=false' \
        | tee "${work_dir}/systemd.log"

    if grep -q 'GOWAVE_SYSTEMD_TEST_PASS' "${work_dir}/systemd.log"; then
        echo "PASS: QEMU Cold Boot acceptance verified for $target_distro."
    else
        echo "ERROR: Guest did not complete the systemd suite successfully for $target_distro." >&2
        if [[ "$clean_work_dir" -eq 1 ]]; then
            rm -rf "$work_dir"
        fi
        return 1
    fi

    if [[ "$clean_work_dir" -eq 1 ]]; then
        rm -rf "$work_dir"
    fi
}

TARGET="${1:-${DISTRO:-docker.io/library/ubuntu:24.04}}"
WORK_DIR="${WORK_DIR:-}"

case "$TARGET" in
    all)
        echo "Executing QEMU Cold Boot Acceptance Matrix across all 4 supported distributions..."
        for d in "${SUPPORTED_DISTROS[@]}"; do
            boot_single_distro "$d" "$WORK_DIR"
        done
        echo "ALL 4 DISTRIBUTIONS PASSED QEMU COLD BOOT ACCEPTANCE."
        ;;
    ubuntu24|ubuntu:24.04|*ubuntu:24.04*)
        boot_single_distro "docker.io/library/ubuntu:24.04" "$WORK_DIR"
        ;;
    ubuntu26|ubuntu:26.04|*ubuntu:26.04*)
        boot_single_distro "docker.io/library/ubuntu:26.04" "$WORK_DIR"
        ;;
    debian12|debian:12|*debian:12*)
        boot_single_distro "docker.io/library/debian:12" "$WORK_DIR"
        ;;
    debian13|debian:13|*debian:13*)
        boot_single_distro "docker.io/library/debian:13" "$WORK_DIR"
        ;;
    *)
        boot_single_distro "$TARGET" "$WORK_DIR"
        ;;
esac
