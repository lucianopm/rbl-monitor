#!/usr/bin/env bash
# Atualização via Git para instalações já existentes do RBL Monitor.
# Preserva DB, .env, config.json, rbls.json e a unidade systemd local.
set -Eeuo pipefail
umask 077
APP_DIR=/opt/rbl-monitor
SERVICE=rbl-monitor.service
REPO_URL='https://github.com/lucianopm/rbl-monitor.git'
BRANCH=main
REPO_ARG=0
BRANCH_ARG=0
YES=0
TMP=''
BACKUP=''
SERVICE_STOPPED=0
SWAPPED_VENV=0
COMPLETE=0
NEXT_CREATED=0
updated=()
STAMP="$(date +%Y%m%d-%H%M%S)"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERRO: %s\n' "$*" >&2; exit 1; }
usage() {
 cat <<'HELP'
Uso: sudo bash /opt/rbl-monitor/update.sh --repo URL [--branch main] [--yes]
     sudo bash /opt/rbl-monitor/update.sh [--yes]   # origem oficial por padrão
     sudo bash /opt/rbl-monitor/update.sh --main   # versão estável
     sudo bash /opt/rbl-monitor/update.sh --dev    # desenvolvimento

Busca uma versão do Git em um diretório temporário, valida seus arquivos,
prepara as dependências em outro virtualenv, cria backup e atualiza os arquivos
mantendo banco, senhas e configurações. Reinicia o serviço, valida /health e
tenta reverter o código/dependências se houver falha.

Por padrão usa https://github.com/lucianopm/rbl-monitor.git (main).
Uma origem salva em .git-update.conf ou --repo pode substituir esse padrão.
Os backups ficam em /opt/rbl-monitor/backups (recomenda-se cópia externa).
Somente execute com repositórios Git de origem confiável.
HELP
}
while (($#)); do
 case "$1" in
   --repo) (($# >= 2)) || fail 'Faltou URL para --repo'; REPO_URL="$2"; REPO_ARG=1; shift 2;;
   --branch) (($# >= 2)) || fail 'Faltou branch para --branch'; BRANCH="$2"; BRANCH_ARG=1; shift 2;;
   --main) BRANCH=main; BRANCH_ARG=1; shift;;
   --dev) BRANCH=dev; BRANCH_ARG=1; shift;;
   --yes) YES=1; shift;;
   -h|--help) usage; exit 0;;
   *) fail "Parâmetro desconhecido: $1";;
 esac
done
[[ "$EUID" -eq 0 ]] || fail 'Execute usando sudo.'
[[ -d "$APP_DIR" && -f "$APP_DIR/.env" && -d "$APP_DIR/data" ]] || fail "Instalação não localizada em $APP_DIR"
[[ -f "$APP_DIR/rbl-monitor.service" ]] || fail 'Unidade local do systemd ausente.'
for local_file in .env config.json rbls.json rbl-monitor.service data/monitor.db; do
 [[ ! -L "$APP_DIR/$local_file" ]] || fail "Arquivo local não pode ser symlink: $local_file"
done
grep -qx 'RBL_MONITOR_DB=/opt/rbl-monitor/data/monitor.db' "$APP_DIR/.env" || fail 'O atualizador exige o caminho padrão de banco em .env.'
for cmd in git python3 curl systemctl tar mktemp flock; do command -v "$cmd" >/dev/null || fail "Dependência não disponível: $cmd"; done
[[ ! -L "$APP_DIR/.update.lock" ]] || fail 'Lock não pode ser symlink.'
exec 9>"$APP_DIR/.update.lock"
flock -n 9 || fail 'Já existe uma atualização em andamento.'
[[ ! -L "$APP_DIR" && ! -L "$APP_DIR/data" && ! -L "$APP_DIR/.venv" ]] || fail 'Diretórios locais não podem ser symlinks.'
[[ -d "$APP_DIR/.venv" && -x "$APP_DIR/.venv/bin/python" ]] || fail 'Ambiente Python existente ausente.'

# Não executa código de shell armazenado em arquivo de configurações.
CONFIG="$APP_DIR/.git-update.conf"
if [[ -f "$CONFIG" ]]; then
  [[ ! -L "$CONFIG" ]] || fail 'Configuração Git não pode ser symlink.'
  while IFS='=' read -r key val || [[ -n "$key" ]]; do
    case "$key" in
      REPO_URL) ((REPO_ARG)) || REPO_URL="$val";;
      BRANCH) ((BRANCH_ARG)) || BRANCH="$val";;
    esac
  done < "$CONFIG"
fi
[[ -n "$REPO_URL" ]] || REPO_URL='https://github.com/lucianopm/rbl-monitor.git'
[[ "$REPO_URL" != *$'\n'* && "$REPO_URL" != *$'\r'* ]] || fail 'URL inválida.'
[[ "$BRANCH" =~ ^[[:alnum:]_.-]{1,120}$ && "$BRANCH" != -* ]] || fail 'Branch inválida.'
[[ "$BRANCH" == main || "$BRANCH" == dev ]] || fail 'Escolha --main ou --dev (ou --branch main|dev).'
if [[ "$BRANCH" == dev ]]; then
 log 'Canal dev: versão de desenvolvimento. Recomenda-se usar em homologação.'
fi
[[ "$REPO_URL" == https://* || "$REPO_URL" == ssh://* || "$REPO_URL" == git@* || "$REPO_URL" == /* ]] || fail 'Use HTTPS, SSH ou caminho Git local confiável.'
if ((!YES)); then
 [[ -t 0 ]] || fail 'Use --yes no modo não interativo.'
 printf 'Atualizar RBL Monitor de %s (branch %s)? [s/N] ' "$REPO_URL" "$BRANCH"
 read -r answer
 [[ "$answer" =~ ^[sS]$ ]] || fail 'Cancelado.'
fi
TMP="$(mktemp -d /tmp/rbl-monitor-update.XXXXXXXX)"
cleanup() {
 local rc=$?
 trap - EXIT
 if ((rc != 0 && COMPLETE == 0 && SERVICE_STOPPED == 1)); then
  echo 'Atualização interrompida; tentando restaurar código e dependências anteriores...' >&2
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  if [[ -f "$BACKUP/app-before.tar" ]]; then
   for f in "${updated[@]}"; do
    [[ -f "$TMP/existed/$f" ]] || rm -f -- "$APP_DIR/$f"
   done
   tar -C "$APP_DIR" -xf "$BACKUP/app-before.tar" || true
  fi
  if ((SWAPPED_VENV)) && [[ -d "$APP_DIR/.venv.previous" ]]; then
   rm -rf -- "$APP_DIR/.venv"
   mv -- "$APP_DIR/.venv.previous" "$APP_DIR/.venv" || true
  fi
  if [[ -f "$BACKUP/service-before" ]]; then
   cp -p -- "$BACKUP/service-before" "$APP_DIR/rbl-monitor.service"
   systemctl daemon-reload || true
  fi
  if [[ -f "$BACKUP/monitor.db" && -f "$BACKUP/database-stopped" ]]; then
   rm -f -- "$APP_DIR/data/monitor.db-wal" "$APP_DIR/data/monitor.db-shm"
   cp -- "$BACKUP/monitor.db" "$APP_DIR/data/monitor.db"
   chown rblmonitor:rblmonitor "$APP_DIR/data/monitor.db"
   chmod 0600 "$APP_DIR/data/monitor.db"
  fi
  systemctl restart "$SERVICE" || true
  if ! curl -fsS --max-time 5 "http://127.0.0.1:${PORT:-8080}/health" >/dev/null; then
   echo 'ATENÇÃO: rollback não confirmou saúde. Verifique systemctl/journalctl e o backup.' >&2
  fi
  echo "Backup disponível: $BACKUP" >&2
 fi
 if ((NEXT_CREATED)) && [[ -d "$APP_DIR/.venv.next" ]]; then rm -rf -- "$APP_DIR/.venv.next"; fi
 [[ -z "$TMP" ]] || rm -rf -- "$TMP"
 exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
log 'Baixando código da origem Git'
GIT_TERMINAL_PROMPT=0 git clone -q --depth 1 --single-branch --branch "$BRANCH" -- "$REPO_URL" "$TMP/repo"
COMMIT="$(git -C "$TMP/repo" rev-parse --short=12 HEAD)"
for name in app.py extensions.py wsgi.py requirements.txt config.json rbls.json install.sh update.sh; do
  [[ -f "$TMP/repo/$name" && ! -L "$TMP/repo/$name" ]] || fail "Arquivo ausente no repositório: $name"
done
[[ -d "$TMP/repo/templates" && -d "$TMP/repo/static" ]] || fail 'Interface incompleta no repositório.'
[[ -z "$(find "$TMP/repo" -type l -print -quit)" ]] || fail 'Pacote contém links simbólicos; operação cancelada.'
# Recusa qualquer arquivo de dados, credencial ou ambiente versionado por acidente.
if git -C "$TMP/repo" ls-files | grep -v -E '(^|/)\.env\.example$' | grep -E '(^|/)(\.env(\..*)?|.*\.db(-.*)?|.*\.sqlite(3)?|\.git-update\.conf|backups|data|\.venv)(/|$)' >/dev/null; then
 fail 'Há arquivos de configuração sensível ou banco versionados. Atualização bloqueada.'
fi
python3 - "$TMP/repo" <<'PY'
import json, pathlib, sys
p=pathlib.Path(sys.argv[1])
for n in ('config.json','rbls.json'):
    json.loads((p/n).read_text(encoding='utf-8'))
for n in ('app.py','extensions.py','wsgi.py'):
    compile((p/n).read_bytes(),str(p/n),'exec')
PY
bash -n "$TMP/repo/install.sh" "$TMP/repo/update.sh"
log "Versão Git obtida: $COMMIT"

log 'Preparando novo ambiente Python sem interromper o serviço'
NEXT="$APP_DIR/.venv.next"
[[ ! -e "$NEXT" ]] || fail "Ambiente temporário antigo encontrado: $NEXT. Remova manualmente após conferência."
python3 -m venv "$NEXT"
NEXT_CREATED=1
if ! "$NEXT/bin/python" -m pip install --disable-pip-version-check -r "$TMP/repo/requirements.txt"; then
 rm -rf -- "$NEXT"
 fail 'Instalação das dependências falhou. Serviço anterior continua inalterado.'
fi
chmod -R a+rX "$NEXT"

# Cópia de segurança com transação SQLite consistente; o DB não deve ser copiado
# com cp enquanto a aplicação está gravando. Nunca mostrar conteúdo das chaves.
BACKUP_DIR="$APP_DIR/backups"
mkdir -p -m 0700 "$BACKUP_DIR"
[[ ! -L "$BACKUP_DIR" ]] || fail 'Backups não podem usar symlink.'
chmod 0700 "$BACKUP_DIR"
BACKUP="$BACKUP_DIR/${STAMP}-${COMMIT}"
[[ ! -e "$BACKUP" ]] || fail 'Já existe backup com o mesmo nome.'
mkdir -m 0700 "$BACKUP"
log "Criando backup: $BACKUP"
if [[ -f "$APP_DIR/data/monitor.db" ]]; then
 python3 - "$APP_DIR/data/monitor.db" "$BACKUP/monitor.db" <<'PY'
import sqlite3, sys
source=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro', uri=True)
target=sqlite3.connect(sys.argv[2])
try:
    source.backup(target)
finally:
    target.close(); source.close()
PY
fi
for name in .env config.json rbls.json .git-update.conf; do
 [[ ! -f "$APP_DIR/$name" ]] || cp -p -- "$APP_DIR/$name" "$BACKUP/$name"
done
# Snapshot do código e demais arquivos persistentes menores, sem bancos, senhas e bibliotecas.
tar -C "$APP_DIR" -cf "$BACKUP/app-before.tar" \
 --exclude='./.venv' --exclude='./.venv.next' --exclude='./.venv.previous' \
 --exclude='./data' --exclude='./backups' --exclude='./.env' \
 --exclude='./.git-update.conf' .

# Lista de arquivos atualizados; protege ajustes locais de JSON, banco e segredos.
# A unidade systemd é gerada pelo instalador e não é atualizada por este script.
mapfile -d '' -t tracked < <(git -C "$TMP/repo" ls-files -z)
updated=()
for file in "${tracked[@]}"; do
 case "$file" in
   .env|.env.*|config.json|rbls.json|rbl-monitor.service|data/*|backups/*|.venv/*|.git* ) continue;;
 esac
 [[ -f "$TMP/repo/$file" ]] || continue
 [[ "$file" != *$'\n'* && "$file" != *$'\r'* ]] || fail 'Nome de arquivo inválido.'
 parent="$APP_DIR"
 IFS='/' read -r -a components <<< "$file"
 for component in "${components[@]}"; do
  parent="$parent/$component"
  [[ ! -L "$parent" ]] || fail "Destino local é symlink: $parent"
 done
 updated+=("$file")
done

mkdir -p "$TMP/existed"
for f in "${updated[@]}"; do
 if [[ -f "$APP_DIR/$f" ]]; then mkdir -p "$TMP/existed/$(dirname "$f")"; touch "$TMP/existed/$f"; fi
done
[[ ! -e "$APP_DIR/.venv.previous" ]] || fail 'Existe ambiente anterior pendente; verifique antes de atualizar.'
log 'Parando serviço e aplicando atualização'
systemctl stop "$SERVICE"
SERVICE_STOPPED=1
# Capture again with the service stopped: rollback includes migrations and writes.
if [[ -f "$APP_DIR/data/monitor.db" ]]; then
 python3 - "$APP_DIR/data/monitor.db" "$BACKUP/monitor.db" <<'PY_STOPPED'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as target:
    source.backup(target)
PY_STOPPED
 touch "$BACKUP/database-stopped"
fi
cp -p -- "$APP_DIR/rbl-monitor.service" "$BACKUP/service-before"
# Python virtualenv entry-point scripts contain absolute paths. Invoke a module
# through the relocated Python executable, instead of a stale gunicorn shebang.
sed -i 's|/\.venv/bin/gunicorn |/.venv/bin/python -m gunicorn |' "$APP_DIR/rbl-monitor.service"
systemctl daemon-reload
for file in "${updated[@]}"; do
 target="$APP_DIR/$file"
 mkdir -p "$(dirname "$target")"
 chmod 0755 "$(dirname "$target")"
 mode=0644
 case "$file" in *.sh) mode=0755;; esac
 install -o root -g rblmonitor -m "$mode" -- "$TMP/repo/$file" "$target.next-file"
 mv -f -- "$target.next-file" "$target"
done
mv -- "$APP_DIR/.venv" "$APP_DIR/.venv.previous"
SWAPPED_VENV=1
mv -- "$NEXT" "$APP_DIR/.venv"
# Reforça permissões do banco. Apenas data/ precisa ser gravável pelo usuário do serviço.
chown -R rblmonitor:rblmonitor "$APP_DIR/data"
chown -R root:rblmonitor "$APP_DIR/.venv" "$APP_DIR/templates" "$APP_DIR/static"
chown root:rblmonitor "$APP_DIR" "$APP_DIR/config.json" "$APP_DIR/rbls.json" "$APP_DIR/rbl-monitor.service"
chown root:root "$APP_DIR/.env" "$BACKUP_DIR"
chmod 0600 "$APP_DIR/.env"

log 'Iniciando serviço e verificando /health'
systemctl restart "$SERVICE"
PORT="$(sed -n 's/.*--bind 0\.0\.0\.0:\([0-9][0-9]*\).*/\1/p' "$APP_DIR/rbl-monitor.service" | head -1)"
PORT="${PORT:-8080}"
healthy=0
for i in $(seq 1 35); do
 if curl -fsS --max-time 3 "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then healthy=1; break; fi
 sleep 1
done
[[ "$healthy" -eq 1 ]] || fail 'Falha na verificação /health. Consulte journalctl.'
# Armazena origem e versão somente após a validação.
printf 'REPO_URL=%s\nBRANCH=%s\n' "$REPO_URL" "$BRANCH" > "$CONFIG.next"
chmod 0600 "$CONFIG.next"
mv -f "$CONFIG.next" "$CONFIG"
printf '%s\n' "$COMMIT" > "$APP_DIR/.git-version"
chmod 0644 "$APP_DIR/.git-version"
COMPLETE=1
rm -rf -- "$APP_DIR/.venv.previous"
log "Atualização concluída (Git $COMMIT). Backup mantido em $BACKUP"
