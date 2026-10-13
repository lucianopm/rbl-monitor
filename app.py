import json
import ipaddress
import logging
import os
import socket
import sqlite3
import threading
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.exception
import dns.resolver
from flask import Flask, flash, g, redirect, render_template, request, url_for

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("RBL_MONITOR_DB", os.path.join(BASE, "monitor.db"))
RBL_FILE = os.path.join(BASE, "rbls.json")
CONFIG_FILE = os.path.join(BASE, "config.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("rbl-monitor")

app = Flask(__name__)
app.secret_key = os.environ.get("RBL_MONITOR_SECRET")

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

CONFIG = load_json(CONFIG_FILE)

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

@app.template_filter("br_datetime")
def br_datetime(value):
    if not value:
        return "—"
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        from zoneinfo import ZoneInfo
        dt = dt.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(os.getenv("TZ", "America/Sao_Paulo")))
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except (TypeError, ValueError):
        return value

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS monitored_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_id INTEGER NOT NULL,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL,
        total_rbls INTEGER NOT NULL DEFAULT 0,
        listed_count INTEGER NOT NULL DEFAULT 0,
        error_count INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(ip_id) REFERENCES monitored_ips(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        check_id INTEGER NOT NULL,
        rbl_name TEXT NOT NULL,
        rbl_zone TEXT NOT NULL,
        status TEXT NOT NULL,
        response TEXT,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(check_id) REFERENCES checks(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_checks_ip_date
      ON checks(ip_id, checked_at DESC);
    CREATE INDEX IF NOT EXISTS idx_results_check
      ON results(check_id);

    -- Dados de rDNS/FCrDNS vinculados a cada execução; tabelas anteriores são preservadas.
    CREATE TABLE IF NOT EXISTS dns_identity_results (
        check_id INTEGER PRIMARY KEY REFERENCES checks(id) ON DELETE CASCADE,
        rdns_status TEXT NOT NULL,
        fcrdns_status TEXT NOT NULL,
        ptr_names TEXT NOT NULL DEFAULT '',
        forward_addresses TEXT NOT NULL DEFAULT '',
        rdns_details TEXT NOT NULL DEFAULT '',
        fcrdns_details TEXT NOT NULL DEFAULT '',
        duration_ms INTEGER NOT NULL DEFAULT 0
    );

    -- Controle de frequência persistente para solicitações de visitantes sem login.
    CREATE TABLE IF NOT EXISTS public_recheck_requests (
        request_key TEXT PRIMARY KEY,
        requested_at INTEGER NOT NULL
    );
    """)
    # Migração aditiva: o banco, os históricos e os usuários permanecem intactos.
    check_columns = {column[1] for column in conn.execute("PRAGMA table_info(checks)")}
    if "check_type" not in check_columns:
        conn.execute("ALTER TABLE checks ADD COLUMN check_type TEXT NOT NULL DEFAULT 'FULL'")
    if "retry_zone" not in check_columns:
        conn.execute("ALTER TABLE checks ADD COLUMN retry_zone TEXT NOT NULL DEFAULT ''")
    result_columns = {column[1] for column in conn.execute("PRAGMA table_info(results)")}
    if "checked_at" not in result_columns:
        conn.execute("ALTER TABLE results ADD COLUMN checked_at TEXT")
    conn.commit()
    conn.close()

def load_rbls():
    return [x for x in effective_rbls() if x.get("enabled", True)]

def reverse_ip(ip):
    """Return the reversed address used by DNSBL query names (without arpa suffix)."""
    obj = ipaddress.ip_address(ip)
    if obj.version == 4:
        return ".".join(reversed(str(obj).split(".")))
    # IPv6 DNSBLs use reversed hexadecimal nibbles, without the ip6.arpa suffix.
    return obj.reverse_pointer.removesuffix(".ip6.arpa")

def rbl_result(rbl, status, response, start):
    return {
        "name": rbl["name"],
        "zone": rbl["zone"],
        "status": status,
        "response": response,
        "duration_ms": int((time.perf_counter() - start) * 1000)
    }

def classify_no_nameservers(exc):
    """Classify dnspython's aggregated resolver failures without leaking query data."""
    errors = getattr(exc, "errors", []) or []
    error_text = " ".join(str(item) for item in errors).upper()
    full_text = f"{error_text} {str(exc)}".upper()
    if "REFUSED" in full_text or "RCODE 5" in full_text:
        return "REFUSED", "DNS server refused the query"
    if "SERVFAIL" in full_text or "RCODE 2" in full_text:
        return "DNS_ERROR", "DNS server returned SERVFAIL"
    return "DNS_ERROR", "DNS query failed/no nameserver response"


SPAMHAUS_ERROR_CODES = {
    "127.255.255.252": "Spamhaus: zona DNS inválida (127.255.255.252). Revise a configuração da RBL.",
    "127.255.255.254": "Spamhaus: consulta recusada pelo resolvedor DNS público/aberto (127.255.255.254). Use DNS recursivo próprio ou configure a chave DQS no painel RBLs.",
    "127.255.255.255": "Spamhaus: limite de consultas excedido (127.255.255.255). Verifique o volume ou use a chave DQS.",
}


def provider_key(name, env_name):
    # Uma configuração salva pelo administrador (inclusive vazia) prevalece sobre a variável de ambiente.
    return str(get_setting(name, os.environ.get(env_name, ""))).strip()


SPAMRATS_CODES = {
    "spam.spamrats.com": "127.0.0.38",
    "dyna.spamrats.com": "127.0.0.36",
    "noptr.spamrats.com": "127.0.0.37",
    "auth.spamrats.com": "127.0.0.43",
    "all.spamrats.com": {"127.0.0.36", "127.0.0.37", "127.0.0.38", "127.0.0.43"},
}


def check_one_rbl(ip, rbl):
    start = time.perf_counter()
    zone = str(rbl["zone"]).strip().lower().rstrip(".")
    secret_key = ""
    is_spamhaus = zone == "zen.spamhaus.org"
    is_spamrats = zone.endswith(".spamrats.com")

    if ipaddress.ip_address(ip).version == 6 and not rbl.get("supports_ipv6", False):
        return rbl_result(rbl, "NOT_SUPPORTED", "IPv6 não habilitado para esta RBL", start)

    if is_spamrats:
        secret_key = provider_key("spamrats_api_key", "SPAMRATS_API_KEY")
        if not secret_key:
            return rbl_result(rbl, "NOT_CONFIGURED", "SpamRATS: informe a chave de API em Configurações de RBLs.", start)
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", secret_key):
            return rbl_result(rbl, "NOT_CONFIGURED", "SpamRATS: chave de API inválida (use letras, números e hífen).", start)
        query_zone = f"{secret_key}.{zone}"
        safe_query = f"{reverse_ip(ip)}.[API_KEY].{zone}"
    elif rbl.get("requires_api_key"):
        # Não enviar credenciais SpamRATS para provedores arbitrários.
        return rbl_result(rbl, "NOT_CONFIGURED", "Esta RBL exige uma chave própria; configuração específica não suportada.", start)
    elif is_spamhaus:
        secret_key = provider_key("spamhaus_dqs_key", "SPAMHAUS_DQS_KEY")
        if secret_key and not re.fullmatch(r"[A-Za-z0-9]{1,63}", secret_key):
            return rbl_result(rbl, "NOT_CONFIGURED", "Spamhaus: chave DQS inválida.", start)
        query_zone = f"{secret_key}.zen.dq.spamhaus.net" if secret_key else zone
        safe_query = f"{reverse_ip(ip)}.[DQS_KEY].zen.dq.spamhaus.net" if secret_key else f"{reverse_ip(ip)}.{zone}"
    else:
        query_zone = zone
        safe_query = f"{reverse_ip(ip)}.{zone}"

    query = f"{reverse_ip(ip)}.{query_zone}"
    resolver = dns.resolver.Resolver()
    timeout = max(0.5, min(30, float(get_setting("dns_timeout_seconds", CONFIG.get("dns_timeout_seconds", 4)))))
    resolver.timeout = timeout
    resolver.lifetime = timeout
    nameservers = ",".join(str(ns) for ns in resolver.nameservers) or "system-default"
    logger.info("[RBL-DNS] start ip=%s list=%s query=%s resolver=%s timeout=%ss",
                ip, rbl.get("name", zone), safe_query, nameservers, timeout)
    try:
        answers = resolver.resolve(query, "A")
        answer_set = {str(answer).strip() for answer in answers}
        response = ", ".join(sorted(answer_set))
        if is_spamhaus:
            # 127.255.255.x NÃO indica listagem, inclusive quando outro registro vem junto.
            errors = [SPAMHAUS_ERROR_CODES.get(code, f"Spamhaus: código de erro DNS ({code}).")
                      for code in answer_set if code.startswith("127.255.255.")]
            if errors:
                return rbl_result(rbl, "DNS_ERROR", " ".join(errors) + f" Resposta: {response}", start)
            valid = {code for code in answer_set if re.fullmatch(r"127\.0\.0\.(?:[2-9]|10|11)", code)}
        elif is_spamrats:
            expected = SPAMRATS_CODES.get(zone)
            if expected:
                expected_set = expected if isinstance(expected, set) else {expected}
                valid = answer_set.intersection(expected_set)
            else:
                valid = {code for code in answer_set if code.startswith("127.") and not code.startswith("127.255.255.")}
        else:
            allowed = rbl.get("listed_codes")
            valid = answer_set.intersection(allowed) if allowed else {
                code for code in answer_set if code.startswith("127.") and not code.startswith("127.255.255.")
            }
        if not valid:
            return rbl_result(rbl, "DNS_ERROR", "Resposta DNS não reconhecida como listagem: " + response, start)
        logger.info("[RBL-DNS] finish ip=%s list=%s status=LISTED response=%s duration_ms=%s",
                    ip, rbl.get("name", zone), response, int((time.perf_counter() - start) * 1000))
        return rbl_result(rbl, "LISTED", response, start)
    except dns.resolver.NXDOMAIN:
        logger.info("[RBL-DNS] finish ip=%s list=%s status=CLEAN rcode=NXDOMAIN duration_ms=%s",
                    ip, rbl.get("name", zone), int((time.perf_counter() - start) * 1000))
        return rbl_result(rbl, "CLEAN", "NXDOMAIN: IP não listado", start)
    except (dns.exception.Timeout, socket.timeout):
        logger.warning("[RBL-DNS] finish ip=%s list=%s status=TIMEOUT duration_ms=%s",
                       ip, rbl.get("name", zone), int((time.perf_counter() - start) * 1000))
        return rbl_result(rbl, "TIMEOUT", "Tempo limite da consulta DNS esgotado", start)
    except dns.resolver.NoNameservers as exc:
        status, response = classify_no_nameservers(exc)
        if zone == "l2.apews.org" and "SERVFAIL" in response:
            response = "APEWS Level 2: servidor DNS retornou SERVFAIL. A consulta falhou; não significa que o IP esteja listado. Considere desativar esta RBL."
        logger.warning("[RBL-DNS] finish ip=%s list=%s status=%s detail=%s duration_ms=%s",
                       ip, rbl.get("name", zone), status, response, int((time.perf_counter() - start) * 1000))
        return rbl_result(rbl, status, response, start)
    except dns.resolver.NoAnswer:
        return rbl_result(rbl, "DNS_ERROR", "Resposta DNS sem registro A", start)
    except Exception as exc:
        # Exceções do resolvedor podem incluir a query completa, incluindo chaves privadas.
        safe_error = str(exc).replace(secret_key, "[CHAVE_OCULTA]") if secret_key else str(exc)
        logger.error("[RBL-DNS] finish ip=%s list=%s status=DNS_ERROR exception_type=%s duration_ms=%s",
                     ip, rbl.get("name", zone), type(exc).__name__, int((time.perf_counter() - start) * 1000))
        return rbl_result(rbl, "DNS_ERROR", safe_error, start)

def check_dns_identity(ip):
    """Valida PTR (rDNS) e a confirmação A/AAAA -> IP original (FCrDNS).

    PASS no FCrDNS exige pelo menos um nome PTR que resolva para o IP consultado.
    Erros temporários não são confundidos com falha definitiva de confirmação.
    """
    started = time.perf_counter()
    result = {
        "rdns_status": "ERROR", "fcrdns_status": "NOT_AVAILABLE",
        "ptr_names": "", "forward_addresses": "",
        "rdns_details": "", "fcrdns_details": "",
        "duration_ms": 0,
    }

    def finish():
        result["duration_ms"] = int((time.perf_counter() - started) * 1000)
        return result

    address = ipaddress.ip_address(ip)
    family = "A" if address.version == 4 else "AAAA"
    try:
        resolver = dns.resolver.Resolver()
        timeout = max(0.5, min(30.0, float(get_setting("dns_timeout_seconds", CONFIG.get("dns_timeout_seconds", 4)))))
        resolver.timeout = timeout
        resolver.lifetime = timeout
    except (OSError, ValueError, dns.exception.DNSException):
        result.update(rdns_details="Não foi possível inicializar o resolvedor DNS.",
                      fcrdns_details="Não aplicável: consulta PTR não executada.")
        return finish()

    try:
        ptr_records = resolver.resolve(address.reverse_pointer, "PTR")
        # Evita uma quantidade ilimitada de consultas caso existam muitos PTRs.
        all_hostnames = sorted({str(record.target).rstrip(".") for record in ptr_records if str(record.target).rstrip(".")})
        hostnames = all_hostnames[:20]
        truncated = len(all_hostnames) > len(hostnames)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(rdns_status="MISSING", rdns_details="Não foi encontrado registro PTR para o IP.",
                      fcrdns_details="Não aplicável: não há PTR para validar.")
        return finish()
    except (dns.exception.Timeout, socket.timeout):
        result.update(rdns_status="TIMEOUT", rdns_details="Tempo limite na consulta PTR.",
                      fcrdns_details="Não foi possível validar o encaminhamento sem o PTR.")
        return finish()
    except dns.resolver.NoNameservers as exc:
        _, description = classify_no_nameservers(exc)
        result.update(rdns_details="Consulta PTR falhou: " + description,
                      fcrdns_details="Não foi possível validar o encaminhamento sem o PTR.")
        return finish()
    except dns.exception.DNSException:
        result.update(rdns_details="Erro na consulta PTR.",
                      fcrdns_details="Não foi possível validar o encaminhamento sem o PTR.")
        return finish()

    if not hostnames:
        result.update(rdns_status="MISSING", rdns_details="O PTR não retornou nomes válidos.",
                      fcrdns_details="Não aplicável: não há PTR para validar.")
        return finish()

    result["rdns_status"] = "PASS"
    result["ptr_names"] = "\n".join(hostnames)
    result["rdns_details"] = f"{len(all_hostnames)} nome(s) PTR encontrado(s)." + (" Consultados os primeiros 20 PTRs (limite de segurança)." if truncated else "")

    details = []
    confirmed = []
    errors = []
    failures = []
    for hostname in hostnames:
        try:
            forward = resolver.resolve(hostname, family)
            ips = sorted({str(ipaddress.ip_address(str(answer))) for answer in forward})
            shown = ips[:50]
            extra = f" (+{len(ips)-50} outros)" if len(ips) > 50 else ""
            details.append(f"{hostname} → {', '.join(shown) if shown else 'sem endereços'}{extra}")
            if ip in ips:
                confirmed.append(hostname)
            else:
                failures.append(hostname)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            details.append(f"{hostname} → sem registro {family}")
            failures.append(hostname)
        except (dns.exception.Timeout, socket.timeout):
            details.append(f"{hostname} → timeout na consulta {family}")
            errors.append(hostname)
        except dns.resolver.NoNameservers as exc:
            _, reason = classify_no_nameservers(exc)
            details.append(f"{hostname} → {reason}")
            errors.append(hostname)
        except (dns.exception.DNSException, ValueError):
            details.append(f"{hostname} → erro na resposta DNS")
            errors.append(hostname)

    result["forward_addresses"] = "\n".join(details)
    if confirmed:
        result["fcrdns_status"] = "PASS"
        result["fcrdns_details"] = "FCrDNS confirmado: " + ", ".join(confirmed)
    elif errors or truncated:
        result["fcrdns_status"] = "ERROR"
        result["fcrdns_details"] = "Não foi possível concluir a validação: houve falha DNS ou nem todos os nomes PTR foram consultados."
    else:
        result["fcrdns_status"] = "FAIL"
        result["fcrdns_details"] = "Nenhum nome PTR consultado retornou o IP original nos registros " + family + "."
    return finish()


_check_lock = threading.Lock()
RETRYABLE_RBL_STATUSES = frozenset({"TIMEOUT", "ERROR", "DNS_ERROR", "REFUSED"})


def run_check(ip_id):
    # One check at a time per process: manual checks and scheduler cannot overlap.
    with _check_lock:
        return _run_check(ip_id)


def _run_check(ip_id):
    conn = db()
    item = conn.execute(
        "SELECT * FROM monitored_ips WHERE id=? AND enabled=1", (ip_id,)
    ).fetchone()
    conn.close()
    if not item:
        return None

    ip = item["ip"]
    rbls = load_rbls()
    started = time.perf_counter()
    # Sempre valida a identidade DNS do IP, mesmo que não exista RBL habilitada.
    try:
        dns_identity = check_dns_identity(ip)
    except Exception:
        logger.exception("Erro inesperado ao validar rDNS/FCrDNS do IP %s", ip)
        dns_identity = {
            "rdns_status": "ERROR", "fcrdns_status": "ERROR",
            "ptr_names": "", "forward_addresses": "",
            "rdns_details": "Falha interna na verificação PTR.",
            "fcrdns_details": "Validação não concluída.", "duration_ms": 0,
        }
    results = []

    workers = max(1, min(32, int(CONFIG.get("max_concurrent_rbls", 20)), len(rbls)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check_one_rbl, ip, rbl) for rbl in rbls]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x["name"].lower())
    listed = sum(1 for x in results if x["status"] == "LISTED")
    errors = sum(1 for x in results if x["status"] in {"ERROR", "TIMEOUT", "REFUSED", "DNS_ERROR", "NOT_CONFIGURED", "NOT_SUPPORTED"})
    status = "LISTED" if listed else ("ERROR" if errors or not results else "CLEAN")
    duration = int((time.perf_counter() - started) * 1000)

    conn = db()
    # The IP may have been deleted or changed while DNS queries were in flight.
    current = conn.execute("SELECT ip, enabled FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
    if not current or current["ip"] != ip or not current["enabled"]:
        conn.close()
        return None
    checked_at = now()
    cur = conn.execute("""
        INSERT INTO checks
        (ip_id, checked_at, status, total_rbls, listed_count, error_count, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ip_id, checked_at, status, len(results), listed, errors, duration))
    check_id = cur.lastrowid
    conn.execute("""INSERT INTO dns_identity_results
        (check_id, rdns_status, fcrdns_status, ptr_names, forward_addresses,
         rdns_details, fcrdns_details, duration_ms)
        VALUES (:check_id, :rdns_status, :fcrdns_status, :ptr_names, :forward_addresses,
                :rdns_details, :fcrdns_details, :duration_ms)""",
        {"check_id": check_id, **dns_identity})
    conn.executemany("""
        INSERT INTO results
        (check_id, rbl_name, rbl_zone, status, response, duration_ms, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [(check_id, x["name"], x["zone"], x["status"], x["response"], x["duration_ms"], checked_at)
          for x in results])
    record_incidents(conn, ip_id, checked_at, results)
    conn.commit()
    conn.close()
    deliver_alerts()
    return check_id

def retry_one_rbl(ip_id, result_id):
    """Consulta apenas o par IP/RBL solicitado e registra um novo snapshot identificado.

    Todas as demais respostas são copiadas com seus horários originais. A consulta
    PTR/FCrDNS não é repetida. Se outra varredura atualizar o IP, a tentativa
    obsoleta é descartada sem sobrescrever resultados mais recentes.
    """
    with _check_lock:
        conn = db()
        try:
            item = conn.execute("SELECT ip,enabled FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
            previous = conn.execute("SELECT * FROM checks WHERE ip_id=? ORDER BY id DESC LIMIT 1", (ip_id,)).fetchone()
            target = (conn.execute("SELECT * FROM results WHERE id=? AND check_id=?",
                                   (result_id, previous["id"])).fetchone() if previous else None)
            if not item or not item["enabled"] or not target or target["status"] not in RETRYABLE_RBL_STATUSES:
                return None
            active_rbl = next((r for r in load_rbls() if r["zone"] == target["rbl_zone"]), None)
            if active_rbl is None:
                return None
            ip = item["ip"]
            previous_id = previous["id"]
        finally:
            conn.close()

        try:
            fresh = check_one_rbl(ip, active_rbl)
        except Exception:
            logger.exception("Falha na tentativa individual de %s para IP %s", active_rbl["zone"], ip)
            fresh = {"name": active_rbl["name"], "zone": active_rbl["zone"], "status": "DNS_ERROR",
                     "response": "Falha interna durante a consulta DNS isolada.", "duration_ms": 0}
        checked_at = now()
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT ip,enabled FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
            latest = conn.execute("SELECT id FROM checks WHERE ip_id=? ORDER BY id DESC LIMIT 1", (ip_id,)).fetchone()
            if not current or not current["enabled"] or current["ip"] != ip or not latest or latest["id"] != previous_id:
                conn.rollback()
                logger.info("Retry descartado: IP %s atualizado durante a consulta", ip)
                return None
            # Pode ter sido desativada enquanto a consulta DNS estava em andamento.
            from extensions import enabled_rbl_zones
            if active_rbl["zone"] not in enabled_rbl_zones(conn):
                conn.rollback()
                return None
            previous_results = conn.execute("SELECT * FROM results WHERE check_id=? ORDER BY id", (previous_id,)).fetchall()
            if not any(row["id"] == result_id for row in previous_results):
                conn.rollback()
                return None
            rows = []
            for old in previous_results:
                if old["id"] == result_id:
                    rows.append((fresh["name"], fresh["zone"], fresh["status"], fresh["response"], fresh["duration_ms"], checked_at))
                else:
                    rows.append((old["rbl_name"], old["rbl_zone"], old["status"], old["response"],
                                 old["duration_ms"], old["checked_at"] or previous["checked_at"]))
            listed = sum(row[2] == "LISTED" for row in rows)
            errors = sum(row[2] in {"ERROR", "TIMEOUT", "REFUSED", "DNS_ERROR", "NOT_CONFIGURED", "NOT_SUPPORTED"} for row in rows)
            status = "LISTED" if listed else ("ERROR" if errors or not rows else "CLEAN")
            cur = conn.execute("""INSERT INTO checks
                (ip_id, checked_at, status, total_rbls, listed_count, error_count, duration_ms, check_type, retry_zone)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'RETRY', ?)""",
                (ip_id, checked_at, status, len(rows), listed, errors, fresh["duration_ms"], active_rbl["zone"]))
            check_id = cur.lastrowid
            conn.executemany("""INSERT INTO results
                (check_id,rbl_name,rbl_zone,status,response,duration_ms,checked_at)
                VALUES (?,?,?,?,?,?,?)""", [(check_id, *row) for row in rows])
            # Reutiliza a última identidade DNS, deixando explícita na interface a data da consulta completa.
            conn.execute("""INSERT INTO dns_identity_results
                (check_id,rdns_status,fcrdns_status,ptr_names,forward_addresses,
                 rdns_details,fcrdns_details,duration_ms)
                SELECT ?,rdns_status,fcrdns_status,ptr_names,forward_addresses,
                       rdns_details,fcrdns_details,duration_ms
                  FROM dns_identity_results WHERE check_id=?""", (check_id, previous_id))
            record_incidents(conn, ip_id, checked_at, [fresh])
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        deliver_alerts()
        return check_id


def run_all():
    conn = db()
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM monitored_ips WHERE enabled=1 ORDER BY id"
    ).fetchall()]
    conn.close()
    # IPs are checked sequentially; each IP's RBL queries are parallel.
    for ip_id in ids:
        try:
            run_check(ip_id)
        except Exception as exc:
            print(f"[ERROR] check {ip_id}: {exc}", flush=True)

def scheduler():
    if CONFIG.get("check_on_start", False):
        run_all()
    while True:
        interval = max(1, int(get_setting("check_interval_minutes", float(CONFIG.get("check_interval_hours", 24)) * 60))) * 60
        if schedule_changed.wait(interval):
            schedule_changed.clear()
            continue
        try:
            run_all()
            deliver_alerts()
        except Exception:
            logger.exception("Falha na rotina agendada; nova tentativa no próximo intervalo")

def current_incident_counts(conn):
    """Operational alert counts, independent of past DNS check results."""
    from extensions import enabled_rbl_zones
    enabled = enabled_rbl_zones(conn)
    result = {}
    rows = conn.execute("""SELECT i.ip_id, i.rbl_zone,
        CASE WHEN ig.ip_id IS NOT NULL THEN 1 ELSE 0 END AS ignored
        FROM incidents i LEFT JOIN incident_ignores ig
        ON ig.ip_id=i.ip_id AND ig.rbl_zone=i.rbl_zone
        WHERE i.cleared_at IS NULL""").fetchall()
    for r in rows:
        info = result.setdefault(r["ip_id"], {"active": 0, "ignored": 0})
        if r["ignored"] or r["rbl_zone"] not in enabled:
            info["ignored"] += 1
        else:
            info["active"] += 1
    return result


def operational_status(last_status, active, ignored):
    if active:
        return "LISTED"
    if ignored:
        return "IGNORED"
    if last_status == "LISTED":
        return "NO_ALERT"  # Latest DNS test may be old; it is not an active alert.
    return last_status


@app.route("/")
def index():
    conn = db()
    raw_rows = conn.execute("""
        SELECT m.*, c.checked_at, c.status AS check_status, c.error_count,
               d.rdns_status,d.fcrdns_status
        FROM monitored_ips m
        LEFT JOIN checks c ON c.id=(SELECT id FROM checks WHERE ip_id=m.id ORDER BY id DESC LIMIT 1)
        LEFT JOIN dns_identity_results d ON d.check_id=c.id
        ORDER BY m.description COLLATE NOCASE, m.ip
    """).fetchall()
    counts = current_incident_counts(conn)
    rows = []
    for entry in raw_rows:
        row = dict(entry)
        state = counts.get(row["id"], {"active": 0, "ignored": 0})
        row["listed_count"] = state["active"]
        row["ignored_count"] = state["ignored"]
        row["status"] = operational_status(row["check_status"], state["active"], state["ignored"])
        rows.append(row)
    stats = {
        "total": len(rows),
        "active": sum(1 for r in rows if r["enabled"]),
        "listed": sum(1 for r in rows if r["status"] == "LISTED"),
        "clean": sum(1 for r in rows if r["checked_at"] and r["status"] in {"CLEAN", "IGNORED", "NO_ALERT"}),
    }
    conn.close()
    return render_template("index.html", rows=rows, stats=stats)

@app.route("/ip/new", methods=["GET", "POST"])
def new_ip():
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        desc = request.form.get("description", "").strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            flash("IP inválido.", "error")
            return render_template("ip_form.html", item=None)
        try:
            conn = db()
            conn.execute(
                "INSERT INTO monitored_ips (ip, description, enabled, created_at) VALUES (?, ?, 1, ?)",
                (ip, desc, now())
            )
            conn.commit()
            item_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.close()
            flash("IP cadastrado com sucesso.", "success")
            return redirect(url_for("ip_detail", ip_id=item_id))
        except sqlite3.IntegrityError:
            conn.rollback()
            conn.close()
            flash("Este IP já está cadastrado.", "error")
    return render_template("ip_form.html", item=None)

@app.route("/ip/<int:ip_id>/edit", methods=["GET", "POST"])
def edit_ip(ip_id):
    conn = db()
    item = conn.execute("SELECT * FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
    if not item:
        conn.close()
        return "IP não encontrado", 404
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        desc = request.form.get("description", "").strip()
        enabled = 1 if request.form.get("enabled") else 0
        try:
            ip = str(ipaddress.ip_address(ip))
            if item["ip"] != ip:
                flash("Para preservar o histórico, cadastre o novo endereço como outro IP.", "error")
                conn.close()
                return redirect(url_for("edit_ip", ip_id=ip_id))
            conn.execute(
                "UPDATE monitored_ips SET ip=?, description=?, enabled=? WHERE id=?",
                (ip, desc, enabled, ip_id)
            )
            conn.commit()
            conn.close()
            flash("IP atualizado.", "success")
            return redirect(url_for("ip_detail", ip_id=ip_id))
        except ValueError:
            flash("IP inválido.", "error")
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Este IP já está cadastrado.", "error")
    conn.close()
    return render_template("ip_form.html", item=item)

@app.post("/ip/<int:ip_id>/delete")
def delete_ip(ip_id):
    conn = db()
    conn.execute("DELETE FROM monitored_ips WHERE id=?", (ip_id,))
    conn.commit()
    conn.close()
    flash("IP removido e histórico apagado.", "success")
    return redirect(url_for("index"))

@app.post("/ips/bulk-add")
def bulk_add_ips():
    raw = request.form.get("ips", "")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    added = 0
    skipped = 0
    invalid = 0
    duplicates = 0

    conn = db()
    seen = set()
    for line in lines:
        # Accept: IP, IP;Description, or IP | Description
        if ";" in line:
            ip, desc = line.split(";", 1)
        elif "|" in line:
            ip, desc = line.split("|", 1)
        else:
            ip, desc = line, ""
        ip = ip.strip()
        desc = desc.strip()

        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            invalid += 1
            continue

        if ip in seen:
            duplicates += 1
            continue
        seen.add(ip)

        try:
            conn.execute(
                "INSERT INTO monitored_ips (ip, description, enabled, created_at) VALUES (?, ?, 1, ?)",
                (ip, desc, now())
            )
            added += 1
        except sqlite3.IntegrityError:
            duplicates += 1

    conn.commit()
    conn.close()

    skipped = duplicates + invalid
    flash(
        f"Inclusão em massa concluída: {added} adicionados, {duplicates} duplicados, {invalid} inválidos.",
        "success" if added or not lines else "error"
    )
    return redirect(url_for("index"))

@app.post("/ips/bulk-check")
def bulk_check_ips():
    raw_ids = request.form.getlist("selected_ids")
    ids = []
    for value in raw_ids:
        try:
            ids.append(int(value))
        except ValueError:
            pass

    ids = sorted(set(ids))
    if not ids:
        flash("Nenhum IP foi selecionado para verificar.", "error")
        return redirect(url_for("index"))

    if not submit_checks(ids):
        flash("Já há uma verificação manual em andamento.", "error")
        return redirect(url_for("index"))
    flash(f"Verificação de {len(ids)} IP(s) iniciada em segundo plano.", "success")
    return redirect(url_for("index"))

@app.post("/ips/bulk-delete")
def bulk_delete_ips():
    raw_ids = request.form.getlist("selected_ids")
    ids = []
    for value in raw_ids:
        try:
            ids.append(int(value))
        except ValueError:
            pass

    ids = sorted(set(ids))
    if not ids:
        flash("Nenhum IP foi selecionado.", "error")
        return redirect(url_for("index"))

    conn = db()
    placeholders = ",".join("?" for _ in ids)
    cur = conn.execute(f"DELETE FROM monitored_ips WHERE id IN ({placeholders})", ids)
    removed = cur.rowcount
    conn.commit()
    conn.close()

    flash(f"{removed} IP(s) removido(s) e histórico apagado.", "success")
    return redirect(url_for("index"))

@app.route("/ip/<int:ip_id>")
def ip_detail(ip_id):
    from extensions import enabled_rbl_zones
    conn = db()
    item = conn.execute("SELECT * FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
    if not item:
        conn.close()
        return "IP não encontrado", 404
    checks = conn.execute("SELECT * FROM checks WHERE ip_id=? ORDER BY id DESC LIMIT 100", (ip_id,)).fetchall()
    last = checks[0] if checks else None
    enabled = enabled_rbl_zones(conn)
    ignored = {r[0] for r in conn.execute("SELECT rbl_zone FROM incident_ignores WHERE ip_id=?", (ip_id,)).fetchall()}
    results = []
    if last:
        results = [dict(r) for r in conn.execute(
            "SELECT * FROM results WHERE check_id=? ORDER BY status DESC,rbl_name", (last["id"],)).fetchall()]
        for r in results:
            r["ignored"] = r["rbl_zone"] in ignored
            r["rbl_enabled"] = r["rbl_zone"] in enabled
    dns_identity = conn.execute("SELECT * FROM dns_identity_results WHERE check_id=?", (last["id"],)).fetchone() if last else None
    full_check = conn.execute("SELECT checked_at FROM checks WHERE ip_id=? AND check_type='FULL' ORDER BY id DESC LIMIT 1", (ip_id,)).fetchone()
    dns_identity_checked_at = full_check["checked_at"] if full_check else None
    incidents = [dict(r) for r in conn.execute("SELECT * FROM incidents WHERE ip_id=? ORDER BY id DESC", (ip_id,)).fetchall()]
    for incident in incidents:
        incident["ignored"] = incident["rbl_zone"] in ignored
        incident["rbl_enabled"] = incident["rbl_zone"] in enabled
    counts = current_incident_counts(conn).get(ip_id, {"active": 0, "ignored": 0})
    effective_status = operational_status(last["status"] if last else None, counts["active"], counts["ignored"])
    conn.close()
    return render_template("ip_detail.html", item=item, checks=checks, last=last, results=results,
                           incidents=incidents, dns_identity=dns_identity, effective_status=effective_status,
                           active_alerts=counts["active"], ignored_alerts=counts["ignored"],
                           retryable_statuses=RETRYABLE_RBL_STATUSES,
                           dns_identity_checked_at=dns_identity_checked_at)

@app.post("/ip/<int:ip_id>/rbl/<int:result_id>/retry")
def retry_rbl_now(ip_id, result_id):
    from extensions import enabled_rbl_zones, submit_rbl_retry
    conn = db()
    try:
        item = conn.execute("SELECT enabled FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
        last = conn.execute("SELECT id FROM checks WHERE ip_id=? ORDER BY id DESC LIMIT 1", (ip_id,)).fetchone()
        target = (conn.execute("SELECT status,rbl_zone FROM results WHERE id=? AND check_id=?",
                               (result_id, last["id"])).fetchone() if last else None)
        if not item:
            return "IP não encontrado", 404
        if not item["enabled"] or not target or target["status"] not in RETRYABLE_RBL_STATUSES or target["rbl_zone"] not in enabled_rbl_zones(conn):
            flash("Consulta indisponível ou desatualizada. Atualize os detalhes do IP.", "error")
            return redirect(url_for("ip_detail", ip_id=ip_id))
    finally:
        conn.close()

    # Mesmo limite compartilhado com o botão de varredura completa, evitando abuso público.
    if not getattr(g, "user", None):
        moment = int(time.time())
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for key, cooldown in (("global", 10), (f"ip:{ip_id}", 120)):
                previous = conn.execute("SELECT requested_at FROM public_recheck_requests WHERE request_key=?", (key,)).fetchone()
                if previous and moment - previous[0] < cooldown:
                    conn.rollback()
                    flash(f"Aguarde {cooldown-(moment-previous[0])} segundo(s) antes de solicitar outra verificação pública.", "error")
                    return redirect(url_for("ip_detail", ip_id=ip_id))
            if not submit_rbl_retry(ip_id, result_id):
                conn.rollback()
                flash("Já há uma verificação manual em andamento.", "error")
                return redirect(url_for("ip_detail", ip_id=ip_id))
            for key in ("global", f"ip:{ip_id}"):
                conn.execute("""INSERT INTO public_recheck_requests(request_key,requested_at) VALUES (?,?)
                    ON CONFLICT(request_key) DO UPDATE SET requested_at=excluded.requested_at""", (key, moment))
            conn.commit()
        finally:
            conn.close()
    elif not submit_rbl_retry(ip_id, result_id):
        flash("Já há uma verificação manual em andamento.", "error")
        return redirect(url_for("ip_detail", ip_id=ip_id))
    flash("Nova tentativa iniciada apenas para esta RBL neste IP. Atualize a página para acompanhar.", "success")
    return redirect(url_for("ip_detail", ip_id=ip_id))

@app.post("/ip/<int:ip_id>/check")
def check_now(ip_id):
    conn = db()
    item = conn.execute("SELECT enabled FROM monitored_ips WHERE id=?", (ip_id,)).fetchone()
    conn.close()
    if item is None:
        return "IP não encontrado", 404
    if not item["enabled"]:
        flash("IP desativado; habilite-o para permitir verificações.", "error")
        return redirect(url_for("ip_detail", ip_id=ip_id))

    # Visitantes sem login podem verificar somente IPs existentes, com CSRF e limites
    # persistentes entre processos Gunicorn, evitando uso abusivo do serviço de DNS.
    if not getattr(g, "user", None):
        moment = int(time.time())
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for key, cooldown in (("global", 10), (f"ip:{ip_id}", 120)):
                previous = conn.execute("SELECT requested_at FROM public_recheck_requests WHERE request_key=?", (key,)).fetchone()
                if previous and moment - previous[0] < cooldown:
                    conn.rollback()
                    remaining = cooldown - (moment - previous[0])
                    flash(f"Aguarde {remaining} segundo(s) antes de solicitar outra verificação pública.", "error")
                    return redirect(url_for("ip_detail", ip_id=ip_id))
            if not submit_checks([ip_id]):
                conn.rollback()
                flash("Já há uma verificação manual em andamento.", "error")
                return redirect(url_for("ip_detail", ip_id=ip_id))
            for key in ("global", f"ip:{ip_id}"):
                conn.execute("""INSERT INTO public_recheck_requests(request_key,requested_at) VALUES (?,?)
                    ON CONFLICT(request_key) DO UPDATE SET requested_at=excluded.requested_at""", (key, moment))
            conn.commit()
        finally:
            conn.close()
    elif not submit_checks([ip_id]):
        flash("Já há uma verificação manual em andamento.", "error")
        return redirect(url_for("ip_detail", ip_id=ip_id))

    flash("Verificação de RBL, rDNS e FCrDNS iniciada. Atualize a página para acompanhar o resultado.", "success")
    return redirect(url_for("ip_detail", ip_id=ip_id))

@app.post("/check-all")
def check_all():
    if not submit_checks():
        flash("Já há uma verificação manual em andamento.", "error")
        return redirect(url_for("index"))
    flash("Verificação de todos os IPs iniciada em segundo plano.", "success")
    return redirect(url_for("index"))

from extensions import setup, effective_rbls, get_setting, record_incidents, deliver_alerts, schedule_changed, submit_checks

init_db()
setup(app, db, CONFIG, RBL_FILE, run_check, run_all, retry_one=retry_one_rbl)

if __name__ == "__main__":
    if os.getenv("ENABLE_SCHEDULER", "1") == "1":
        threading.Thread(target=scheduler, daemon=True).start()
    app.run(host=CONFIG.get("host", "0.0.0.0"), port=int(CONFIG.get("port", 8080)), debug=False)
