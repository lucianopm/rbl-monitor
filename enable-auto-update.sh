#!/usr/bin/env bash
# Execute only after configuring and testing update.sh --repo URL.
set -Eeuo pipefail
umask 077
APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ "$APP_DIR" =~ ^/[A-Za-z0-9_./-]+$ ]] || { echo 'Caminho sem espaços/caracteres especiais necessário.' >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo 'Execute com sudo.' >&2; exit 1; }
[[ -f "$APP_DIR/.git-update.conf" ]] || { echo 'Execute primeiro update.sh neste diretório.' >&2; exit 1; }
if [[ ${1:-} == --disable ]]; then
 systemctl disable --now rbl-monitor-update.timer
 exit 0
fi
[[ $# -eq 0 ]] || { echo 'Uso: sudo bash enable-auto-update.sh [--disable]' >&2; exit 1; }
cat > /etc/systemd/system/rbl-monitor-update.service <<UNIT
[Unit]
Description=RBL Monitor Git update with backup and rollback
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/bin/bash $APP_DIR/update.sh --yes
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
