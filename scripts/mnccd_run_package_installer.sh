#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

if [ "$(id -u)" -ne 0 ]; then
    echo "mnccd_run_package_installer.sh must be run as root (e.g. sudo)." >&2
    exit 1
fi

if [ ! -f "${PWD}/nvidia-mnccd.service" ]; then
    echo "Missing nvidia-mnccd.service in ${PWD}" >&2
    exit 1
fi

echo "Starting NVIDIA MNCCD installation"

echo "Copying files to desired location"

install -m 0755 "${PWD}/nvidia-mnccd" /usr/bin/nvidia-mnccd

mkdir -p /etc/nvidia-mnccd
install -m 0600 "${PWD}/mnccd_config.toml" /etc/nvidia-mnccd/mnccd_config.toml

mkdir -p /etc/nvidia-mnccd/tls

mkdir -p /usr/share/nvidia/mnccd/doc
cp "${PWD}/LICENSE" /usr/share/nvidia/mnccd/doc/
cp "${PWD}/third-party-notices.txt" /usr/share/nvidia/mnccd/doc/

SYSTEMD_UNIT_DIR="/usr/lib/systemd/system"
mkdir -p "${SYSTEMD_UNIT_DIR}"
install -m 0644 "${PWD}/nvidia-mnccd.service" "${SYSTEMD_UNIT_DIR}/nvidia-mnccd.service"

echo "Installed ${SYSTEMD_UNIT_DIR}/nvidia-mnccd.service"
echo "Start the service with:"
echo "  systemctl daemon-reload"
echo "  systemctl start nvidia-mnccd"
echo "To start on boot: systemctl enable nvidia-mnccd"
echo "View logs with: journalctl -u nvidia-mnccd.service -f"

echo "MNCCD installation completed."
