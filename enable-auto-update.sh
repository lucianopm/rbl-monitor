#!/usr/bin/env bash
# Execute only after configuring and testing update.sh --repo URL.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Execute com sudo.' >&2; exit 1; }
[[ -f /opt/rbl-monitor/.git-update.conf ]] || { echo 'Configure primeiro update.sh --repo URL.' >&2; exit 1; }
if [[ ${1:-} == --disable ]]; then
 systemctl disable --now rbl-monitor-update.timer
 exit 0
fi
[[ $# -eq 0 ]] || { echo 'Uso: sudo bash enable-auto-update.sh [--disable]' >&2; exit 1; }
cat > /etc/systemd/system/rbl-monitor-update.service <<'UNIT'
[Unit]
Description=RBL Monitor Git update with backup and rollback
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/bin/bash /opt/rbl-monitor/update.sh --yes
UNIT
cat > /etc/systemd/system/rbl-monitor-update.timer <<'UNIT'
[Unit]
Description=Daily RBL Monitor update
[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now rbl-monitor-update.timer
echo 'Atualização diária habilitada às 04h no fuso do servidor (+ até 15 min).'
