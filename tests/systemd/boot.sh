#!/usr/bin/env bash
# tests/systemd/boot.sh - Real systemd guest runner using QEMU TCG for GoWave Auto NGINX
set -Eeuo pipefail

WORK_DIR="${WORK_DIR:-/work}"
REPO_DIR="${REPO_DIR:-/repo}"

mkdir -p "$WORK_DIR"
[[ -s "$WORK_DIR/rootfs.tar" ]] || { echo "ERROR: $WORK_DIR/rootfs.tar is required; refusing to treat a skipped VM as passed." >&2; exit 2; }
command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "ERROR: qemu-system-x86_64 is required." >&2; exit 2; }
command -v cpio >/dev/null 2>&1 || { echo "ERROR: cpio is required." >&2; exit 2; }
command -v gzip >/dev/null 2>&1 || { echo "ERROR: gzip is required." >&2; exit 2; }
command -v timeout >/dev/null 2>&1 || { echo "ERROR: timeout is required." >&2; exit 2; }
[[ -d "$REPO_DIR" ]] || { echo "ERROR: REPO_DIR does not exist: $REPO_DIR" >&2; exit 2; }

rm -f "${WORK_DIR}/reboot-policy.tar" "${WORK_DIR}/pre-boot-id" "${WORK_DIR}/reboot.cpio.gz"
rm -rf "${WORK_DIR}/root"
mkdir -p "${WORK_DIR}/root"

tar -xf "${WORK_DIR}/rootfs.tar" -C "${WORK_DIR}/root"
[[ -x "${WORK_DIR}/root/sbin/init" ]] || { echo "ERROR: rootfs does not contain executable /sbin/init." >&2; exit 2; }

if [[ -d /lib/modules ]]; then
    mkdir -p "${WORK_DIR}/root/usr/lib"
    cp -a /lib/modules "${WORK_DIR}/root/usr/lib/"
fi

mkdir -p "${WORK_DIR}/root/repo"
cp -a "${REPO_DIR}/." "${WORK_DIR}/root/repo/"

rm -f "${WORK_DIR}/root/.dockerenv" "${WORK_DIR}/root/etc/machine-id"

# Configure DNS resolution in rootfs
mkdir -p "${WORK_DIR}/root/etc/systemd"
printf '[Resolve]\nDNS=8.8.8.8 1.1.1.1\n' > "${WORK_DIR}/root/etc/systemd/resolved.conf"
chmod 0644 "${WORK_DIR}/root/etc/systemd/resolved.conf"

mkdir -p "${WORK_DIR}/root/dev" "${WORK_DIR}/root/proc" "${WORK_DIR}/root/sys" "${WORK_DIR}/root/run"

cat > "${WORK_DIR}/root/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
exec /sbin/init
INIT
chmod 0755 "${WORK_DIR}/root/init"

cat > "${WORK_DIR}/root/etc/systemd/system/gowave-ci.service" <<'UNIT'
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

mkdir -p "${WORK_DIR}/root/etc/systemd/system/multi-user.target.wants"
ln -sf ../gowave-ci.service "${WORK_DIR}/root/etc/systemd/system/multi-user.target.wants/gowave-ci.service"

echo "Building initramfs cpio archive..."
cd "${WORK_DIR}/root"
find . -xdev -print0 | cpio --null -o --format=newc 2>"${WORK_DIR}/cpio.log" | gzip -1 > "${WORK_DIR}/rootfs.cpio.gz"

kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -type f 2>/dev/null | sort -V | tail -1)
[[ -n "$kernel" ]] || { echo "ERROR: host kernel image not found under /boot." >&2; exit 2; }

echo "Booting QEMU TCG guest with kernel $kernel..."
timeout 15m qemu-system-x86_64 -machine accel=tcg -m 2048 -smp 2 -nodefaults \
    -no-reboot -display none -serial stdio -monitor none -nic none \
    -kernel "$kernel" -initrd "${WORK_DIR}/rootfs.cpio.gz" \
    -append 'console=ttyS0 panic=1 quiet rdinit=/init systemd.show_status=false' \
    | tee "${WORK_DIR}/systemd.log"

grep -q 'GOWAVE_SYSTEMD_TEST_PASS' "${WORK_DIR}/systemd.log" || {
    echo "ERROR: Guest did not complete the systemd suite successfully." >&2
    exit 1
}
