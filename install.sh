#!/usr/bin/env bash
# RBL Monitor - instalacao integral em /opt/rbl-monitor (Ubuntu/Debian).
# Para reinstalar, remove somente os locais conhecidos do RBL Monitor.
set -Eeuo pipefail
umask 077

APP_DIR=/opt/rbl-monitor
APP_USER=rblmonitor
SERVICE_NAME=rbl-monitor.service
SERVICE_LINK=/etc/systemd/system/rbl-monitor.service
PORT=8080
CONFIRMED=0
SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nERRO: %s\n' "$*" >&2; exit 1; }
trap 'echo "Falha na linha $LINENO; diagnostico: sudo journalctl -u rbl-monitor -n 80 --no-pager" >&2' ERR
usage() {
cat <<'HELP'
Uso: sudo bash install.sh [--yes] [--port 8080]

Instalacao limpa de RBL Monitor (Ubuntu/Debian com systemd).
Todos os arquivos da aplicacao ficam em /opt/rbl-monitor, incluindo
configuracao .env, banco SQLite, .venv, unidade systemd e logs via journalctl.
A unica referencia fora do diretorio e o registro obrigatorio do servico
no systemd (links gerenciados pelo sistema).

Uma instalacao antiga faz o instalador cancelar sem apagar dados.
Use update.sh para atualizar. --yes permanece aceito por compatibilidade.
Senha admin e chave de sessao sao geradas automaticamente no servidor.
HELP
}
while (( $# )); do
  case "$1" in
    --yes) CONFIRMED=1; shift ;;
    --port) (( $# >= 2 )) || fail 'Use --port NUMERO'; PORT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Parametro desconhecido: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail 'Execute com sudo: sudo bash install.sh'
[[ -r /etc/os-release ]] || fail 'Sistema operacional nao identificado.'
# shellcheck disable=SC1091
source /etc/os-release
[[ " ${ID:-} ${ID_LIKE:-} " =~ (debian|ubuntu) ]] || fail 'Suporta Ubuntu/Debian.'
command -v apt-get >/dev/null || fail 'apt-get nao encontrado.'
[[ -d /run/systemd/system ]] || fail 'E necessario um servidor Linux com systemd ativo.'
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || fail 'Porta invalida.'
PORT=$((10#$PORT))
(( PORT >= 1024 && PORT <= 65535 )) || fail 'Use uma porta entre 1024 e 65535.'
[[ "$SOURCE" != "$APP_DIR" ]] || fail 'Extraia o ZIP em outro local, por exemplo seu HOME, antes de executar.'
for file in app.py extensions.py wsgi.py requirements.txt config.json rbls.json README.md install.sh update.sh; do
  [[ -f "$SOURCE/$file" && ! -L "$SOURCE/$file" ]] || fail "Arquivo ausente: $file"
done
[[ -d "$SOURCE/templates" && -d "$SOURCE/static" ]] || fail 'Pastas templates/static ausentes.'
[[ -z "$(find "$SOURCE/templates" "$SOURCE/static" -type l -print -quit)" ]] || fail 'Templates/static não podem conter symlinks.'

# Caminhos EXATOS de versoes antigas; nao toca em sites/servicos de terceiros.
OLD_PATHS=(
  "$APP_DIR"
  /var/lib/rbl-monitor
  /etc/rbl-monitor.env
  "$SERVICE_LINK"
  /etc/nginx/sites-available/rbl-monitor
  /etc/nginx/sites-enabled/rbl-monitor
  /etc/nginx/sites-available/rbl-monitor.conf
  /etc/nginx/sites-enabled/rbl-monitor.conf
  /etc/nginx/conf.d/rbl-monitor.conf
)
existing=()
for path in "${OLD_PATHS[@]}"; do
  [[ -e "$path" || -L "$path" ]] && existing+=("$path")
done
if ((${#existing[@]})); then
  fail 'Instalação anterior detectada. Use update.sh. Para reinstalar, faça backup e remova manualmente apenas os caminhos conferidos; este instalador não apaga dados existentes.'
fi

log 'Instalando dependencias necessarias'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip openssl curl ca-certificates git

log 'Validando o pacote antes de apagar arquivos anteriores'
python3 - "$SOURCE" <<'PY_CHECK'
import json, pathlib, sys
assert sys.version_info >= (3,10), 'Python 3.10 ou superior necessário'
p=pathlib.Path(sys.argv[1])
for name in ('config.json','rbls.json'):
    json.loads((p/name).read_text(encoding='utf-8'))
for name in ('app.py','extensions.py','wsgi.py'):
    compile((p/name).read_bytes(),str(p/name),'exec')
PY_CHECK

log 'Copiando a aplicacao para um unico diretorio'
if ! id "$APP_USER" &>/dev/null; then
  useradd --system --user-group --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
else
  usermod --home "$APP_DIR" "$APP_USER"
fi
install -d -m 0755 -o root -g root "$APP_DIR"
install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$APP_DIR/data"
for name in app.py extensions.py wsgi.py requirements.txt config.json rbls.json install.sh update.sh README.md; do
  install -m 0644 "$SOURCE/$name" "$APP_DIR/$name"
done
chmod 0755 "$APP_DIR/install.sh" "$APP_DIR/update.sh"
for name in INSTALACAO.md USO.md ATUALIZACAO_GIT.md SEGURANCA.md VALIDACAO.md TROUBLESHOOTING.md .gitignore .env.example enable-auto-update.sh; do
  [[ ! -f "$SOURCE/$name" ]] || install -m 0644 "$SOURCE/$name" "$APP_DIR/$name"
done
cp -a -- "$SOURCE/templates" "$SOURCE/static" "$APP_DIR/"

log 'Preparando Python e instalando bibliotecas'
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -r "$APP_DIR/requirements.txt"
chmod -R a+rX "$APP_DIR/.venv" "$APP_DIR/templates" "$APP_DIR/static"

log 'Gerando senha e chave aleatorias localmente'
SECRET="$(openssl rand -hex 32)"
ADMIN_PASS="$(openssl rand -hex 20)"
cat > "$APP_DIR/.env" <<EOF
RBL_MONITOR_DB=$APP_DIR/data/monitor.db
RBL_MONITOR_SECRET=$SECRET
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASS
ENABLE_SCHEDULER=1
TZ=America/Sao_Paulo
COOKIE_SECURE=0
EOF
chown root:root "$APP_DIR/.env"
chmod 0600 "$APP_DIR/.env"

log 'Criando servico systemd dentro da pasta da aplicacao'
cat > "$APP_DIR/rbl-monitor.service" <<EOF
[Unit]
Description=RBL Monitor (interno)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP_DIR/.venv/bin/python -m gunicorn --workers 1 --threads 8 --bind 0.0.0.0:$PORT --timeout 120 --access-logfile - wsgi:app
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
# SQLite precisa criar arquivos -wal e -shm junto ao banco principal.
chown -R root:root "$APP_DIR"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/data"
chmod 0700 "$APP_DIR/data"
chmod 0600 "$APP_DIR/.env"
chmod 0755 "$APP_DIR"
chmod 0644 "$APP_DIR/rbl-monitor.service"

log 'Registrando e iniciando o servico'
systemctl link "$APP_DIR/rbl-monitor.service"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

check_health() {
  for i in $(seq 1 35); do
    if curl -fsS --max-time 3 "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
      return 0
    fi
    sleep 1
  done
  return 1
}
log 'Verificando aplicacao, banco vazio e conta administrativa'
if ! check_health; then
  journalctl -u "$SERVICE_NAME" -n 80 --no-pager || true
  fail 'Servico nao respondeu ao /health.'
fi
"$APP_DIR/.venv/bin/python" - "$APP_DIR/data/monitor.db" <<'PY_VERIFY'
import sqlite3,sys
con=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)
assert con.execute("SELECT COUNT(*) FROM users WHERE username='admin' AND is_admin=1 AND active=1").fetchone()[0]==1, 'Administrador nao criado'
assert con.execute('SELECT COUNT(*) FROM monitored_ips').fetchone()[0]==0, 'O banco nao esta vazio'
con.close()
PY_VERIFY

log 'Removendo senha inicial do arquivo de ambiente'
# A senha permanece armazenada no SQLite apenas como hash.
sed -i '/^ADMIN_PASSWORD=/d' "$APP_DIR/.env"
chmod 0600 "$APP_DIR/.env"
systemctl restart "$SERVICE_NAME"
check_health || fail 'O servico falhou ao reiniciar depois da configuracao.'

printf '\n============================================================\n'
printf 'RBL MONITOR INSTALADO DO ZERO\n'
printf 'Acesso: http://IP_DO_SERVIDOR:%s/login\n' "$PORT"
printf 'Usuario: admin\n'
printf 'Senha inicial (anote agora): %s\n' "$ADMIN_PASS"
printf 'Diretorio unico: %s\n' "$APP_DIR"
printf 'Servico: sudo systemctl status rbl-monitor\n'
printf 'Logs: sudo journalctl -u rbl-monitor -f\n'
printf '============================================================\n'
printf '\nUse apenas em rede interna confiavel; HTTP nao criptografa senhas.\n'
unset SECRET ADMIN_PASS
