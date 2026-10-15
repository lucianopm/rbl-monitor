"""Access control, incidents, settings and durable alerts."""
import json
import logging
import os
import re
import secrets
import smtplib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, flash, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from version_info import build_label

schedule_changed = threading.Event()
_jobs = ThreadPoolExecutor(max_workers=1, thread_name_prefix="manual-check")
_job_pending = threading.Lock()
_mail_lock = threading.Lock()
_db = None
_config = None
_rbl_file = None
_run_one = None
_run_all = None
_retry_one = None

DELISTING = {
    "zen.spamhaus.org": "https://check.spamhaus.org/",
    "b.barracudacentral.org": "https://www.barracudacentral.org/rbl/removal-request",
    "bl.spamcop.net": "https://www.spamcop.net/bl.shtml",
    "dnsbl.dronebl.org": "https://dronebl.org/lookup",
    **{f"{s}.spamrats.com": "https://www.spamrats.com/removal.php" for s in ("all", "spam", "dyna", "noptr", "auth")},
}


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_setting(key, default=""):
    if _db is None:
        return default
    with _db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def set_setting(conn, key, value):
    conn.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def valid_url(value):
    parsed = urlsplit(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and not parsed.username and not parsed.password


def delisting_url(zone):
    value = str(get_setting("delisting:" + zone, DELISTING.get(zone, "")))
    return value if value and valid_url(value) else ""


def effective_rbls():
    with open(_rbl_file, encoding="utf-8") as handle:
        sources = json.load(handle)
    overrides = json.loads(get_setting("rbl_overrides", "{}"))
    extra = json.loads(get_setting("extra_rbls", "[]"))
    sources.extend(extra)
    for source in sources:
        source.update(overrides.get(source["zone"], {}))
    return sources


def enabled_rbl_zones(conn=None):
    """Current enabled zones, honoring saved settings (not old check history)."""
    if conn is None:
        source = get_setting("rbl_overrides", "{}")
        extra = get_setting("extra_rbls", "[]")
    else:
        rows = dict(conn.execute("SELECT key,value FROM settings WHERE key IN ('rbl_overrides','extra_rbls')").fetchall())
        source = rows.get("rbl_overrides", "{}")
        extra = rows.get("extra_rbls", "[]")
    overrides = json.loads(source)
    with open(_rbl_file, encoding="utf-8") as handle:
        configured = json.load(handle)
    configured.extend(json.loads(extra))
    return {r["zone"] for r in configured if overrides.get(r["zone"], {}).get("enabled", r.get("enabled", True))}


def close_disabled_incidents(conn):
    """Disabled RBLs have no active alert; keep all historical incidents."""
    enabled = sorted(enabled_rbl_zones(conn))
    restriction = "AND rbl_zone NOT IN (" + ",".join("?" for _ in enabled) + ")" if enabled else ""
    conn.execute("UPDATE incidents SET cleared_at=?, closure_reason='DISABLED' WHERE cleared_at IS NULL " + restriction,
                 (timestamp(), *enabled))


def record_incidents(conn, ip_id, checked_at, results, notify=True):
    # Ignore results from a scan that was started before an RBL was disabled.
    enabled = enabled_rbl_zones(conn)
    for result in results:
        zone, status = result["zone"], result["status"]
        if zone not in enabled:
            continue
        ignored = conn.execute("SELECT 1 FROM incident_ignores WHERE ip_id=? AND rbl_zone=?", (ip_id, zone)).fetchone()
        active = conn.execute("SELECT id FROM incidents WHERE ip_id=? AND rbl_zone=? AND cleared_at IS NULL", (ip_id, zone)).fetchone()
        if status == "LISTED":
            if active:
                conn.execute("UPDATE incidents SET last_seen_at=?,response=? WHERE id=?", (checked_at, result["response"], active[0]))
            else:
                cursor = conn.execute("INSERT INTO incidents(ip_id,rbl_zone,rbl_name,detected_at,last_seen_at,response) VALUES (?,?,?,?,?,?)", (ip_id, zone, result["name"], checked_at, checked_at, result["response"]))
                if notify:
                    recipients = conn.execute("SELECT value FROM settings WHERE key='alert_recipients'").fetchone()
                    enabled_row = conn.execute("SELECT value FROM settings WHERE key='alert_enabled'").fetchone()
                    notifications_enabled = (enabled_row[0] == "1") if enabled_row else bool(recipients and recipients[0].strip())
                    if recipients and recipients[0].strip() and notifications_enabled and not ignored:
                        conn.execute("INSERT INTO alert_outbox(incident_id,recipients,created_at) VALUES (?,?,?)", (cursor.lastrowid, recipients[0], timestamp()))
        elif status == "CLEAN" and active:
            conn.execute("UPDATE incidents SET cleared_at=?,closure_reason='CLEAN' WHERE id=?", (checked_at, active[0]))
        # DNS/access errors never clear an existing block.


def smtp_value(key, env_key, default=""):
    """Configurações da interface têm prioridade sobre o ambiente legado."""
    return str(get_setting(key, os.getenv(env_key, default))).strip()


def smtp_security():
    legacy = "ssl" if os.getenv("SMTP_USE_SSL", "0") == "1" else (
        "starttls" if os.getenv("SMTP_USE_TLS", "1") == "1" else "none"
    )
    return smtp_value("smtp_security", "SMTP_SECURITY", legacy)


def smtp_config():
    try:
        port = int(smtp_value("smtp_port", "SMTP_PORT", "587"))
    except ValueError:
        port = 587
    return {
        "host": smtp_value("smtp_host", "SMTP_HOST"),
        "port": port,
        "security": smtp_security(),
        "username": smtp_value("smtp_username", "SMTP_USERNAME"),
        "password": get_setting("smtp_password", os.getenv("SMTP_PASSWORD", "")),
        "sender": smtp_value("smtp_from", "SMTP_FROM", smtp_value("smtp_username", "SMTP_USERNAME")),
    }


def valid_email(address):
    # Aceita também domínios SMTP internos (.local, por exemplo); rejeita injeção de cabeçalhos.
    return bool(re.fullmatch(r"[^\s@<>;,]{1,128}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}", address)) and len(address) <= 254


def parse_recipients(raw):
    # Destinatários podem ser separados por vírgulas, ponto e vírgula ou linhas.
    addresses = [x.strip() for x in re.split(r"[,;\n]+", raw) if x.strip()]
    if len(addresses) > 100 or any(not valid_email(x) for x in addresses):
        raise ValueError("Destinatários inválidos (limite: 100 endereços).")
    return list(dict.fromkeys(addresses))


def alerts_enabled():
    # Quem já recebia alertas pela configuração anterior continua recebendo.
    previous = bool(get_setting("alert_recipients", "").strip())
    return get_setting("alert_enabled", "1" if previous else "0") == "1"


def send_message(recipients, subject, text):
    configuration = smtp_config()
    host, port, security = configuration["host"], configuration["port"], configuration["security"]
    if not host or not 1 <= port <= 65535:
        raise RuntimeError("Servidor SMTP não configurado")
    if security not in {"ssl", "starttls", "none"}:
        raise RuntimeError("Modo de segurança SMTP inválido")
    if not configuration["sender"] or not valid_email(configuration["sender"]):
        raise RuntimeError("Remetente SMTP inválido")
    if not recipients or any(not valid_email(x) for x in recipients):
        raise ValueError("Destinatários inválidos")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = configuration["sender"]
    message["To"] = ", ".join(recipients)
    message.set_content(text)
    import ssl
    context = ssl.create_default_context()
    if security == "ssl":
        client = smtplib.SMTP_SSL(host, port, timeout=15, context=context)
    else:
        client = smtplib.SMTP(host, port, timeout=15)
    with client as smtp:
        if security == "starttls":
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        if configuration["username"]:
            smtp.login(configuration["username"], configuration["password"])
        smtp.send_message(message, to_addrs=recipients)


def deliver_alerts():
    if not alerts_enabled():
        return
    if not _mail_lock.acquire(blocking=False):
        return
    try:
        conn = _db()
        zones = sorted(enabled_rbl_zones(conn))
        placeholders = ",".join("?" for _ in zones)
        pending = conn.execute(f"""SELECT o.*, i.rbl_name,i.rbl_zone,i.detected_at,m.ip,m.description
            FROM alert_outbox o JOIN incidents i ON i.id=o.incident_id
            JOIN monitored_ips m ON m.id=i.ip_id
            WHERE o.sent_at IS NULL AND i.cleared_at IS NULL AND i.rbl_zone IN ({placeholders})
              AND NOT EXISTS (SELECT 1 FROM incident_ignores ig
                  WHERE ig.ip_id=i.ip_id AND ig.rbl_zone=i.rbl_zone)
            ORDER BY o.id LIMIT 50""", zones).fetchall()
        conn.close()
        for row in pending:
            try:
                # An administrator may have muted/disabled the alert while this batch was queued.
                with _db() as guard:
                    muted = guard.execute("""SELECT 1 FROM incidents i
                        LEFT JOIN incident_ignores ig ON ig.ip_id=i.ip_id AND ig.rbl_zone=i.rbl_zone
                        WHERE i.id=? AND (i.cleared_at IS NOT NULL OR ig.ip_id IS NOT NULL)""", (row["incident_id"],)).fetchone()
                    current_zones = enabled_rbl_zones(guard)
                if muted or row["rbl_zone"] not in current_zones:
                    continue
                text = f"Nova listagem detectada\nIP: {row['ip']}\nDescrição: {row['description']}\nRBL: {row['rbl_name']}\nDetectado (UTC): {row['detected_at']}\nConsulta / delisting: {delisting_url(row['rbl_zone']) or 'Não informado'}\n"
                send_message([x.strip() for x in row["recipients"].split(",") if x.strip()], f"[RBL Monitor] {row['ip']} listado em {row['rbl_name']}", text)
                with _db() as conn:
                    conn.execute("UPDATE alert_outbox SET sent_at=?,attempts=attempts+1,last_error='' WHERE id=?", (timestamp(), row["id"]))
                conn.close()
            except Exception as exc:
                # Store only exception class: SMTP exception messages may contain secrets.
                with _db() as conn:
                    conn.execute("UPDATE alert_outbox SET attempts=attempts+1,last_error=? WHERE id=?", (type(exc).__name__, row["id"]))
                conn.close()
    finally:
        _mail_lock.release()


def submit_checks(ids=None):
    if not _job_pending.acquire(blocking=False):
        return False
    def work():
        try:
            if ids is None:
                _run_all()
            else:
                for ip_id in sorted(set(ids)):
                    _run_one(ip_id)
        finally:
            _job_pending.release()
    _jobs.submit(work)
    return True


def submit_rbl_retry(ip_id, result_id):
    """Enfileira uma tentativa individual na mesma fila de verificações manuais."""
    if _retry_one is None or not _job_pending.acquire(blocking=False):
        return False
    def work():
        try:
            _retry_one(ip_id, result_id)
        except Exception:
            logging.getLogger("rbl-monitor").exception("Falha no retry individual: ip_id=%s result_id=%s", ip_id, result_id)
        finally:
            _job_pending.release()
    try:
        _jobs.submit(work)
    except Exception:
        _job_pending.release()
        raise
    return True


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def setup(app, db_factory, config, rbl_file, run_one, run_all, retry_one=None):
    global _db, _config, _rbl_file, _run_one, _run_all, _retry_one
    _db, _config, _rbl_file = db_factory, config, rbl_file
    _run_one, _run_all, _retry_one = run_one, run_all, retry_one
    conn = _db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,is_admin INTEGER NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,ip_id INTEGER NOT NULL REFERENCES monitored_ips(id) ON DELETE CASCADE,
            rbl_zone TEXT NOT NULL,rbl_name TEXT NOT NULL,detected_at TEXT NOT NULL,last_seen_at TEXT NOT NULL,
            cleared_at TEXT,response TEXT,observation TEXT NOT NULL DEFAULT '');
        CREATE UNIQUE INDEX IF NOT EXISTS incident_active ON incidents(ip_id,rbl_zone) WHERE cleared_at IS NULL;
        CREATE TABLE IF NOT EXISTS alert_outbox(id INTEGER PRIMARY KEY,incident_id INTEGER NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
            recipients TEXT NOT NULL,created_at TEXT NOT NULL,sent_at TEXT,attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS login_attempts(username TEXT PRIMARY KEY,failures INTEGER NOT NULL,last_attempt TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS incident_ignores(
            ip_id INTEGER NOT NULL REFERENCES monitored_ips(id) ON DELETE CASCADE,
            rbl_zone TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
            PRIMARY KEY (ip_id, rbl_zone));
    """)
    # Non-destructive, automatic schema evolution for existing SQLite installations.
    if "closure_reason" not in {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}:
        conn.execute("ALTER TABLE incidents ADD COLUMN closure_reason TEXT NOT NULL DEFAULT ''")
    close_disabled_incidents(conn)
    if "session_token" not in {row[1] for row in conn.execute("PRAGMA table_info(users)")}:
        conn.execute("ALTER TABLE users ADD COLUMN session_token TEXT NOT NULL DEFAULT ''")
    secret = os.getenv("RBL_MONITOR_SECRET", "")
    if not secret or secret in {"change-this-secret", "CHANGE-ME"}:
        row = conn.execute("SELECT value FROM settings WHERE key='session_secret'").fetchone()
        secret = row[0] if row else secrets.token_hex(32)
        set_setting(conn, "session_secret", secret)
    app.secret_key = secret
    password = os.getenv("ADMIN_PASSWORD", "")
    if password and not conn.execute("SELECT 1 FROM users").fetchone():
        if len(password) < 10:
            raise RuntimeError("ADMIN_PASSWORD deve ter pelo menos 10 caracteres")
        conn.execute("INSERT INTO users(username,password_hash,is_admin) VALUES (?,?,1)", (os.getenv("ADMIN_USERNAME", "admin"), generate_password_hash(password)))
    conn.execute("UPDATE users SET session_token=lower(hex(randomblob(32))) WHERE session_token=''")
    conn.commit()
    conn.close()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1", PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=1024 * 1024)
    from werkzeug.middleware.proxy_fix import ProxyFix
    if os.getenv("TRUST_PROXY", "0") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    # Authentication runs before CSRF, so unauthenticated mutations redirect to login.
    @app.before_request
    def authenticate():
        if request.endpoint == "health":
            g.user = None
            return None
        conn = _db()
        g.user = conn.execute("SELECT id,username,is_admin FROM users WHERE id=? AND active=1 AND session_token=?",
                              (session.get("user_id"), session.get("user_token", ""))).fetchone()
        conn.close()
        # Nova verificação por IP é pública; demais operações continuam autenticadas.
        public = {"index", "ip_detail", "check_now", "retry_rbl_now", "static", "health", "login"}
        if request.endpoint and request.endpoint not in public and not g.user:
            return redirect(url_for("login"))
    CSRFProtect(app)
    app.jinja_env.globals["delisting_url"] = delisting_url
    @app.context_processor
    def context():
        return {"user": g.get("user"), "timezone_name": os.getenv("TZ", "America/Sao_Paulo"),
                "app_version": build_label()}
    @app.get("/health")
    def health():
        try:
            conn = _db()
            try:
                conn.execute("SELECT id FROM users LIMIT 1").fetchone()
                conn.execute("SELECT id FROM checks LIMIT 1").fetchone()
            finally:
                conn.close()
            return {"status": "ok"}
        except Exception:
            app.logger.error("Health: banco indisponível")
            return {"status": "error"}, 503
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()[:80]
            conn = _db()
            attempt = conn.execute("SELECT * FROM login_attempts WHERE username=?", (username,)).fetchone()
            if attempt and attempt["failures"] >= 10 and datetime.strptime(attempt["last_attempt"], "%Y-%m-%d %H:%M:%S") > datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15):
                conn.close()
                flash("Muitas tentativas. Aguarde 15 minutos.", "error")
                return render_template("login.html"), 429
            account = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
            if account and check_password_hash(account["password_hash"], request.form.get("password", "")):
                conn.execute("DELETE FROM login_attempts WHERE username=?", (username,))
                conn.commit()
                conn.close()
                session.clear()
                session["user_id"] = account["id"]
                session["user_token"] = account["session_token"]
                session.permanent = True
                return redirect(url_for("index"))
            failures = attempt["failures"] + 1 if attempt and datetime.strptime(attempt["last_attempt"], "%Y-%m-%d %H:%M:%S") > datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15) else 1
            conn.execute("INSERT INTO login_attempts VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET failures=excluded.failures,last_attempt=excluded.last_attempt", (username, failures, timestamp()))
            conn.commit()
            conn.close()
            flash("Usuário ou senha inválidos.", "error")
        return render_template("login.html")
    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))
    @app.route("/account", methods=["GET", "POST"])
    def account():
        if request.method == "POST":
            conn = _db()
            row = conn.execute("SELECT password_hash FROM users WHERE id=?", (g.user["id"],)).fetchone()
            password = request.form.get("password", "")
            if len(password) >= 10 and check_password_hash(row[0], request.form.get("current_password", "")):
                token = secrets.token_hex(32)
                conn.execute("UPDATE users SET password_hash=?,session_token=? WHERE id=?", (generate_password_hash(password), token, g.user["id"]))
                session["user_token"] = token
                conn.commit()
                flash("Senha atualizada.", "success")
            else:
                flash("Confira a senha atual e use uma nova senha de 10+ caracteres.", "error")
            conn.close()
        return render_template("account.html")
    @app.post("/incident/<int:incident_id>/note")
    def incident_note(incident_id):
        conn = _db()
        incident = conn.execute("SELECT ip_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not incident:
            conn.close()
            abort(404)
        conn.execute("UPDATE incidents SET observation=? WHERE id=?", (request.form.get("observation", "").strip()[:10000], incident_id))
        conn.commit()
        conn.close()
        return redirect(url_for("ip_detail", ip_id=incident[0]))
    @app.post("/incident/<int:incident_id>/ignore")
    @admin_required
    def incident_ignore(incident_id):
        with _db() as conn:
            incident = conn.execute("SELECT ip_id,rbl_zone FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not incident:
                abort(404)
            conn.execute("""INSERT OR IGNORE INTO incident_ignores(ip_id,rbl_zone,created_at,created_by)
                VALUES (?,?,?,?)""", (incident["ip_id"], incident["rbl_zone"], timestamp(), g.user["username"]))
            # Discard unsent mail; undoing Ignore must not send an old alert.
            conn.execute("""DELETE FROM alert_outbox WHERE sent_at IS NULL AND incident_id IN
                (SELECT id FROM incidents WHERE ip_id=? AND rbl_zone=?)""",
                (incident["ip_id"], incident["rbl_zone"]))
        flash("RBL ignorada para este IP. O bloqueio permanece no histórico, mas não conta como alerta nem gera novos e-mails.", "success")
        return redirect(url_for("ip_detail", ip_id=incident["ip_id"]))

    @app.post("/incident/<int:incident_id>/unignore")
    @admin_required
    def incident_unignore(incident_id):
        with _db() as conn:
            incident = conn.execute("SELECT ip_id,rbl_zone FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not incident:
                abort(404)
            conn.execute("DELETE FROM incident_ignores WHERE ip_id=? AND rbl_zone=?",
                         (incident["ip_id"], incident["rbl_zone"]))
        flash("A RBL voltou a contar nos alertas deste IP.", "success")
        return redirect(url_for("ip_detail", ip_id=incident["ip_id"]))

    @app.post("/incident/<int:incident_id>/dismiss")
    @admin_required
    def incident_dismiss(incident_id):
        with _db() as conn:
            incident = conn.execute("SELECT ip_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not incident:
                abort(404)
            conn.execute("""UPDATE incidents SET cleared_at=?,closure_reason='MANUAL'
                WHERE id=? AND cleared_at IS NULL""", (timestamp(), incident_id))
            conn.execute("DELETE FROM alert_outbox WHERE incident_id=? AND sent_at IS NULL", (incident_id,))
        flash("Alerta encerrado manualmente. Se continuar listado na próxima consulta, um novo alerta poderá surgir. Para evitar isso, use Ignorar.", "success")
        return redirect(url_for("ip_detail", ip_id=incident["ip_id"]))

    @app.route("/admin/users", methods=["GET", "POST"])
    @admin_required
    def users():
        conn = _db()
        if request.method == "POST":
            name, password = request.form.get("username", "").strip(), request.form.get("password", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", name) or len(password) < 10:
                flash("Use usuário de 3–80 caracteres e senha de 10+ caracteres.", "error")
            elif conn.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
                flash("Usuário já existe.", "error")
            else:
                conn.execute("INSERT INTO users(username,password_hash,is_admin,session_token) VALUES (?,?,?,?)", (name, generate_password_hash(password), int(bool(request.form.get("is_admin"))), secrets.token_hex(32)))
                conn.commit()
                flash("Usuário criado.", "success")
        rows = conn.execute("SELECT id,username,is_admin,active FROM users ORDER BY username").fetchall()
        conn.close()
        return render_template("users.html", users=rows)
    @app.post("/admin/users/<int:user_id>/toggle")
    @admin_required
    def user_toggle(user_id):
        return manage_user(user_id, "toggle")

    def manage_user(user_id, action):
        conn = _db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            actor = conn.execute("SELECT * FROM users WHERE id=? AND active=1 AND is_admin=1 AND session_token=?",
                                 (g.user["id"], session.get("user_token", ""))).fetchone()
            if not actor:
                abort(403)
            target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not target:
                abort(404)
            if user_id == actor["id"]:
                flash("Use Minha senha para sua conta. Não é permitido excluir, desativar ou alterar o próprio perfil aqui.", "error")
                return redirect(url_for("users"))
            role = request.form.get("role")
            if action == "role" and role not in {"admin", "operator"}:
                abort(400)
            removes_admin = action == "delete" or (action == "toggle" and target["active"]) or (action == "role" and role == "operator")
            admins = conn.execute("SELECT COUNT(*) FROM users WHERE active=1 AND is_admin=1").fetchone()[0]
            if removes_admin and target["active"] and target["is_admin"] and admins <= 1:
                flash("A última conta administrativa ativa deve ser preservada.", "error")
                return redirect(url_for("users"))
            if action == "password":
                password = request.form.get("password", "")
                if len(password) < 10 or password != request.form.get("password_confirm", ""):
                    flash("Use senha de 10+ caracteres e confirmação idêntica.", "error")
                    return redirect(url_for("users"))
                conn.execute("UPDATE users SET password_hash=?,session_token=? WHERE id=?",
                             (generate_password_hash(password), secrets.token_hex(32), user_id))
                conn.execute("DELETE FROM login_attempts WHERE username=? COLLATE NOCASE", (target["username"],))
            elif action == "delete":
                conn.execute("DELETE FROM login_attempts WHERE username=? COLLATE NOCASE", (target["username"],))
                conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            elif action == "role":
                conn.execute("UPDATE users SET is_admin=?,session_token=? WHERE id=?",
                             (int(role == "admin"), secrets.token_hex(32), user_id))
            else:
                conn.execute("UPDATE users SET active=1-active,session_token=? WHERE id=?", (secrets.token_hex(32), user_id))
            conn.commit()
            flash("Usuário excluído. IPs e histórico preservados." if action == "delete" else
                  "Usuário atualizado. Sessões anteriores dessa conta foram invalidadas.", "success")
        finally:
            conn.close()
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/role")
    @admin_required
    def user_role(user_id):
        return manage_user(user_id, "role")

    @app.post("/admin/users/<int:user_id>/password")
    @admin_required
    def user_password(user_id):
        return manage_user(user_id, "password")

    @app.post("/admin/users/<int:user_id>/delete")
    @admin_required
    def user_delete(user_id):
        return manage_user(user_id, "delete")
    @app.route("/admin/settings", methods=["GET", "POST"])
    @admin_required
    def settings():
        if request.method == "POST":
            try:
                interval = int(request.form.get("interval", ""))
                timeout = float(request.form.get("timeout", ""))
                if not 1 <= interval <= 10080 or not 0.5 <= timeout <= 30:
                    raise ValueError()
                with _db() as conn:
                    set_setting(conn, "check_interval_minutes", interval)
                    set_setting(conn, "dns_timeout_seconds", timeout)
                schedule_changed.set()
                flash("Configurações de monitoramento salvas.", "success")
                return redirect(url_for("settings"))
            except (ValueError, OverflowError):
                flash("Confira o intervalo e o timeout.", "error")
        return render_template("settings.html",
            interval=get_setting("check_interval_minutes", int(float(config.get("check_interval_hours", 24)) * 60)),
            timeout=get_setting("dns_timeout_seconds", config.get("dns_timeout_seconds", 4)))

    @app.route("/admin/smtp", methods=["GET", "POST"])
    @admin_required
    def smtp_settings():
        if request.method == "POST":
            host = request.form.get("smtp_host", "").strip()
            sender = request.form.get("smtp_from", "").strip()
            username = request.form.get("smtp_username", "").strip()
            password = request.form.get("smtp_password", "")
            security = request.form.get("smtp_security", "starttls")
            recipients_raw = request.form.get("recipients", "")
            enabled = bool(request.form.get("alert_enabled"))
            clear_password = bool(request.form.get("clear_smtp_password"))
            errors = []
            try:
                port = int(request.form.get("smtp_port", ""))
                if not 1 <= port <= 65535:
                    errors.append("A porta SMTP precisa estar entre 1 e 65535.")
            except ValueError:
                port = 587
                errors.append("Informe uma porta SMTP válida.")
            if not host or len(host) > 253 or any(c.isspace() or ord(c) < 33 for c in host) or any(c in host for c in "/\\@#?"):
                errors.append("Informe um endereço IP ou nome válido para o servidor SMTP.")
            if security not in {"starttls", "ssl", "none"}:
                errors.append("Selecione um modo de segurança SMTP válido.")
            if sender and not valid_email(sender):
                errors.append("Informe um endereço de remetente válido.")
            if len(username) > 254 or any(c in username for c in "\r\n"):
                errors.append("Usuário SMTP inválido.")
            if len(password) > 1024 or any(c in password for c in "\r\n"):
                errors.append("Senha SMTP inválida.")
            if password and clear_password:
                errors.append("Informe uma nova senha ou marque Remover senha, não ambos.")
            try:
                recipients = parse_recipients(recipients_raw)
            except ValueError as exc:
                errors.append(str(exc))
                recipients = []
            if enabled and (not recipients or not sender):
                errors.append("Para ativar os alertas, informe remetente e destinatários.")
            if errors:
                for error in errors:
                    flash(error, "error")
            else:
                with _db() as conn:
                    for key, value in (
                        ("smtp_host", host), ("smtp_port", port), ("smtp_security", security),
                        ("smtp_username", username), ("smtp_from", sender),
                        ("alert_recipients", ", ".join(recipients)),
                        ("alert_enabled", "1" if enabled else "0"),
                    ):
                        set_setting(conn, key, value)
                    # Campo de senha vazio mantém a senha anterior, sem retornar o segredo ao navegador.
                    if password or clear_password:
                        set_setting(conn, "smtp_password", "" if clear_password else password)
                flash("Servidor SMTP e alertas salvos.", "success")
                return redirect(url_for("smtp_settings"))
        configuration = smtp_config()
        conn = _db()
        zones = sorted(enabled_rbl_zones(conn))
        placeholders = ",".join("?" for _ in zones)
        pending = conn.execute(f"""SELECT COUNT(*) FROM alert_outbox o
            JOIN incidents i ON i.id=o.incident_id
            WHERE o.sent_at IS NULL AND i.cleared_at IS NULL AND i.rbl_zone IN ({placeholders})
            AND NOT EXISTS (SELECT 1 FROM incident_ignores ig
                WHERE ig.ip_id=i.ip_id AND ig.rbl_zone=i.rbl_zone)""", zones).fetchone()[0]
        conn.close()
        from domain_monitor import pending_count
        pending += pending_count()
        return render_template("smtp.html", smtp={k: v for k, v in configuration.items() if k != "password"},
            password_configured=bool(configuration["password"]),
            recipients=get_setting("alert_recipients"),
            alerts_active=alerts_enabled(), pending=pending)

    @app.post("/admin/test-email")
    @admin_required
    def test_email():
        try:
            recipients = parse_recipients(get_setting("alert_recipients"))
            if not recipients:
                flash("Salve ao menos um destinatário antes de testar.", "error")
            else:
                send_message(recipients, "[RBL Monitor] Teste SMTP", "O envio SMTP do RBL Monitor está funcionando.\n")
                flash("E-mail de teste enviado ao servidor SMTP. Verifique a caixa de entrada.", "success")
        except Exception as exc:
            logger = app.logger
            # Não registrar mensagens do servidor SMTP, pois podem conter credenciais.
            logger.warning("Teste SMTP falhou: %s", type(exc).__name__)
            flash("Falha ao enviar teste SMTP: " + type(exc).__name__ + ". Confira endereço, porta, autenticação e TLS.", "error")
        return redirect(url_for("smtp_settings"))
    @app.route("/admin/rbls", methods=["GET", "POST"])
    @admin_required
    def rbls():
        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "save_all":
                sources = effective_rbls()
                known_zones = {r["zone"] for r in sources}
                posted_zones = request.form.getlist("rbl_zone")
                errors = []
                if len(posted_zones) != len(known_zones) or set(posted_zones) != known_zones:
                    errors.append("A lista de RBLs mudou. Atualize a página antes de salvar.")
                updates = {}
                for zone in posted_zones:
                    link = request.form.get("rbl_link:" + zone, "").strip()
                    if link and (len(link) > 1000 or not valid_url(link)):
                        errors.append("URL inválida para " + zone)
                    updates[zone] = {
                        "enabled": "rbl_enabled:" + zone in request.form,
                        "supports_ipv6": "rbl_ipv6:" + zone in request.form,
                        "link": link,
                    }
                keys = {}
                for name, description in (("spamrats_api_key", "SpamRATS"), ("spamhaus_dqs_key", "Spamhaus DQS")):
                    value = request.form.get(name, "").strip()
                    remove = "remove_" + name in request.form
                    if value and remove:
                        errors.append(f"Para {description}, escolha informar ou remover a chave.")
                    if value and not re.fullmatch(r"[A-Za-z0-9-]{1,63}", value):
                        errors.append(f"Chave inválida para {description} (somente letras, números e hífen, até 63 caracteres).")
                    if name == "spamhaus_dqs_key" and value and not re.fullmatch(r"[A-Za-z0-9]{1,63}", value):
                        errors.append("A chave Spamhaus DQS deve conter apenas letras e números.")
                    if value or remove:
                        keys[name] = "" if remove else value
                if errors:
                    for error in errors:
                        flash(error, "error")
                else:
                    with _db() as conn:
                        overrides = json.loads(get_setting("rbl_overrides", "{}"))
                        for zone, value in updates.items():
                            overrides[zone] = {
                                **overrides.get(zone, {}),
                                "enabled": value["enabled"],
                                "supports_ipv6": value["supports_ipv6"],
                            }
                            set_setting(conn, "delisting:" + zone, value["link"])
                        set_setting(conn, "rbl_overrides", json.dumps(overrides))
                        close_disabled_incidents(conn)
                        for name, value in keys.items():
                            set_setting(conn, name, value)
                    flash("Configurações salvas. Alertas das RBLs desativadas foram encerrados sem apagar o histórico.", "success")
                    return redirect(url_for("rbls"))
            elif action == "add":
                zone = request.form.get("zone", "").strip().lower().rstrip(".")
                name = request.form.get("name", "").strip()[:120]
                if not name or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", zone):
                    flash("Informe um nome e uma zona DNS válida.", "error")
                elif any(r["zone"] == zone for r in effective_rbls()):
                    flash("Esta zona DNS já existe.", "error")
                else:
                    with _db() as conn:
                        extra = json.loads(get_setting("extra_rbls", "[]"))
                        extra.append({"name": name, "zone": zone, "enabled": False})
                        set_setting(conn, "extra_rbls", json.dumps(extra))
                    flash("RBL adicionada. Habilite-a e clique em Salvar todas as configurações.", "success")
                    return redirect(url_for("rbls"))
            else:
                flash("Operação inválida.", "error")
        spamrats_key = str(get_setting("spamrats_api_key", os.getenv("SPAMRATS_API_KEY", ""))).strip()
        spamhaus_key = str(get_setting("spamhaus_dqs_key", os.getenv("SPAMHAUS_DQS_KEY", ""))).strip()
        return render_template("rbls.html", rbls=effective_rbls(), spamrats_configured=bool(spamrats_key), spamhaus_configured=bool(spamhaus_key))
