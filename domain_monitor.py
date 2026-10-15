"""Domain monitoring and private, non-persistent ad-hoc DNS analysis.

No HTTP connections are made to submitted domains. DNSBL codes are interpreted
per provider, never by the generic IP-RBL rules. Provider access tests guard
against treating an ACL/NXDOMAIN response as proof of a clean domain.
"""
import ipaddress
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import tldextract
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from extensions import (admin_required, alerts_enabled, get_setting, parse_recipients,
                        send_message, set_setting)

blueprint = Blueprint('domains', __name__, url_prefix='/domains')


@blueprint.after_request
def prevent_report_caching(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

# Bundled PSL snapshot only: no network fetch or cache writes at runtime.
suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
_db = None
_lock = threading.Lock()
PROVIDERS = {
    'dbl': {'name': 'Spamhaus DBL (DQS)', 'zone': 'dbl.dq.spamhaus.net', 'test': 'dbltest.com',
            'link': 'https://www.spamhaus.org/faqs/domain-blocklist/'},
    'uribl': {'name': 'URIBL MULTI', 'zone': 'multi.uribl.com', 'test': 'test.uribl.com',
              'link': 'https://uribl.com/about.shtml'},
    'surbl': {'name': 'SURBL MULTI', 'zone': 'multi.surbl.org', 'test': 'surbl-org-permanent-test-point.com',
              'link': 'https://surbl.org/lists'},
}


@contextmanager
def connection():
    conn = _db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def stamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def normalize_domain(value):
    value = value.strip().rstrip('.').lower()
    if not value or any(c in value for c in '/:@?#\\') or any(c.isspace() for c in value):
        raise ValueError('Informe somente o domínio, sem URL, e-mail, porta ou caminho.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError('Nome de domínio inválido.') from None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Use a área de IPs para endereços IP.')
    if len(value) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
        raise ValueError('Nome de domínio inválido.')
    extracted = suffixes(value)
    if not extracted.suffix or not extracted.domain:
        raise ValueError('Informe um domínio com sufixo público reconhecido (PSL).')
    return value


def normalize_selector(value):
    value = value.strip().lower().rstrip('.')
    if value and (len(value) > 100 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?', value)
                  or '..' in value):
        raise ValueError('Seletor DKIM inválido.')
    return value


def provider_settings():
    return json.loads(get_setting('domain_providers', '{}'))


def query(name, kind):
    """Bounded DNS query; exceptions never escape with secret-bearing names."""
    try:
        resolver = dns.resolver.Resolver()
        timeout = max(0.5, min(8.0, float(get_setting('dns_timeout_seconds', 4))))
        resolver.timeout = resolver.lifetime = timeout
        answers = resolver.resolve(name, kind)
        records = []
        for answer in list(answers)[:30]:
            if kind == 'TXT':
                records.append(b''.join(answer.strings).decode('utf-8', errors='replace')[:4096])
            else:
                records.append(str(answer)[:1000])
        return 'ANSWER', records
    except dns.resolver.NXDOMAIN:
        return 'NXDOMAIN', []
    except dns.resolver.NoAnswer:
        return 'NO_DATA', []
    except dns.exception.Timeout:
        return 'TIMEOUT', []
    except dns.resolver.NoNameservers:
        return 'DNS_ERROR', []
    except Exception:
        return 'DNS_ERROR', []


def classify_codes(provider, codes):
    if not codes:
        return 'DNS_ERROR', 'Resposta vazia.'
    if provider == 'dbl':
        listed = {'127.0.1.' + str(n) for n in (2, 4, 5, 6, 102, 103, 104, 105, 106)}
        if any(code not in listed for code in codes):
            return 'DNS_ERROR', 'Resposta de erro/acesso ou código DBL não reconhecido: ' + ', '.join(codes)
        return 'LISTED', 'Domínio listado na DBL: ' + ', '.join(codes)
    masks = {'uribl': {2: 'black', 4: 'grey', 8: 'red'},
             'surbl': {4: 'disposable', 8: 'phishing', 16: 'malware', 32: 'click tracker', 64: 'abuse', 128: 'cracked'}}[provider]
    labels = set()
    for code in codes:
        try:
            number = int(code.rsplit('.', 1)[1])
        except (ValueError, IndexError):
            return 'DNS_ERROR', 'Código não reconhecido.'
        if not code.startswith('127.0.0.') or number == 0 or number & ~sum(masks):
            return 'DNS_ERROR', 'Consulta recusada ou código não reconhecido: ' + ', '.join(codes)
        labels.update(label for bit, label in masks.items() if number & bit)
    # URIBL red/grey and SURBL click/disposable indicate context, not a block.
    risky = 'black' in labels if provider == 'uribl' else bool(labels & {'phishing', 'malware', 'abuse', 'cracked'})
    return ('LISTED' if risky else 'NOTICE'), 'Categorias: ' + ', '.join(sorted(labels))


def check_provider(domain, provider, settings):
    source = PROVIDERS[provider]
    result = {'provider': provider, 'name': source['name'], 'domain': domain, 'status': 'DISABLED', 'detail': 'Lista desabilitada.'}
    if not settings.get(provider):
        return result
    zone = source['zone']
    if provider == 'dbl':
        # Reuses the existing protected DQS setting; never put keys in reports.
        from app import provider_key
        key = provider_key('spamhaus_dqs_key', 'SPAMHAUS_DQS_KEY')
        if not re.fullmatch(r'[A-Za-z0-9]{1,63}', key):
            return {**result, 'status': 'NOT_CONFIGURED', 'detail': 'Configure a chave Spamhaus DQS no painel RBLs.'}
        zone = key + '.' + zone
    # URI lists require registrable domains; DBL can inspect the exact hostname.
    target = domain if provider == 'dbl' else suffixes(domain).top_domain_under_public_suffix
    result['domain'] = target
    if len(target + '.' + zone) > 253:
        return {**result, 'status': 'DNS_ERROR', 'detail': 'Nome de consulta excede o limite DNS.'}
    state, codes = query(source['test'] + '.' + zone, 'A')
    status, _ = classify_codes(provider, codes) if state == 'ANSWER' else ('DNS_ERROR', '')
    if status != 'LISTED':
        return {**result, 'status': 'ACCESS_ERROR', 'detail': 'Teste positivo do provedor falhou (' + state + '). Nenhum resultado limpo será presumido.'}
    state, codes = query(target + '.' + zone, 'A')
    if state == 'NXDOMAIN':
        return {**result, 'status': 'CLEAN', 'detail': 'Não listado nesta consulta (NXDOMAIN).'}
    if state != 'ANSWER':
        return {**result, 'status': state if state == 'TIMEOUT' else 'DNS_ERROR', 'detail': 'Consulta DNS não concluída: ' + state}
    status, detail = classify_codes(provider, codes)
    return {**result, 'status': status, 'detail': detail}


def txt_check(name, prefix):
    state, records = query(name, 'TXT')
    matches = [value for value in records if value.lower().startswith(prefix.lower())]
    if state in {'TIMEOUT', 'DNS_ERROR'}:
        return {'status': state, 'records': [], 'detail': 'Falha de consulta TXT.'}
    if not matches:
        return {'status': 'MISSING', 'records': [], 'detail': 'Registro não encontrado no nome consultado.'}
    if len(matches) > 1:
        return {'status': 'INVALID', 'records': matches, 'detail': 'Mais de um registro para a mesma política.'}
    return {'status': 'PRESENT', 'records': matches, 'detail': 'Registro localizado; não comprova autenticação de mensagens.'}


def check_auth(domain, selector):
    spf = txt_check(domain, 'v=spf1')
    if spf['status'] == 'PRESENT' and not re.match(r'^v=spf1(?:\s|$)', spf['records'][0], re.I):
        spf.update(status='INVALID', detail='Prefixo SPF inválido.')
    dmarc = txt_check('_dmarc.' + domain, 'v=DMARC1')
    # Organizational-domain fallback only for absence, never for temporary errors.
    base = suffixes(domain).top_domain_under_public_suffix
    inherited = False
    if dmarc['status'] == 'MISSING' and base != domain:
        dmarc = txt_check('_dmarc.' + base, 'v=DMARC1')
        inherited = dmarc['status'] != 'MISSING'
    if dmarc['status'] == 'PRESENT':
        tags = parse_tags(dmarc['records'][0])
        if tags.get('v', '').upper() != 'DMARC1' or tags.get('p') not in {'none', 'quarantine', 'reject'}:
            dmarc.update(status='INVALID', detail='Política DMARC ausente/inválida ou tags duplicadas.')
        else:
            policy = tags.get('sp', tags['p']) if inherited else tags['p']
            dmarc['detail'] = ('Política herdada de ' + base + '. ' if inherited else '') + 'Política publicada: ' + policy
            if policy not in {'none', 'quarantine', 'reject'}:
                dmarc.update(status='INVALID', detail='Política DMARC de subdomínios inválida.')
    if selector:
        dkim = txt_check(selector + '._domainkey.' + domain, '')
        if dkim['status'] == 'PRESENT':
            tags = parse_tags(dkim['records'][0])
            if not tags.get('p') or tags.get('v', 'DKIM1').upper() != 'DKIM1':
                dkim.update(status='INVALID', detail='Chave DKIM ausente, revogada ou formato inválido.')
    else:
        dkim = {'status': 'NOT_CHECKED', 'records': [], 'detail': 'Informe o seletor usado pelo remetente; não há descoberta automática de seletores.'}
    state, mx = query(domain, 'MX')
    return {'SPF': spf, 'DMARC': dmarc, 'DKIM': dkim,
            'MX': {'status': 'PRESENT' if state == 'ANSWER' else state, 'records': mx,
                   'detail': 'MX indica recebimento, não reputação ou autorização de envio.'}}


def parse_tags(record):
    tags = {}
    for part in record.split(';'):
        if not part.strip():
            continue
        if '=' not in part:
            return {}
        key, value = part.strip().split('=', 1)
        key = key.lower().strip()
        if key in tags:
            return {}
        tags[key] = value.strip()
    return tags


def analyze(domain, selector=''):
    domain, selector = normalize_domain(domain), normalize_selector(selector)
    settings = provider_settings()
    # Four independent jobs bound each analysis to approximately six DNS timeouts.
    with ThreadPoolExecutor(max_workers=4) as pool:
        provider_jobs = [pool.submit(check_provider, domain, name, settings) for name in PROVIDERS]
        auth_job = pool.submit(check_auth, domain, selector)
        results = [job.result() for job in provider_jobs]
        auth = auth_job.result()
    enabled = [row for row in results if row['status'] != 'DISABLED']
    listed = sum(row['status'] == 'LISTED' for row in enabled)
    errors = sum(row['status'] not in {'CLEAN', 'LISTED', 'NOTICE'} for row in enabled)
    status = 'LISTED' if listed else 'ERROR' if errors else 'NOTICE' if any(row['status'] == 'NOTICE' for row in enabled) else 'CLEAN' if enabled else 'NOT_CHECKED'
    return {'domain': domain, 'selector': selector, 'checked_at': stamp(), 'status': status,
            'listed_count': listed, 'error_count': errors, 'providers': results, 'auth': auth}


def reserve_request(user_id):
    with connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        last = conn.execute('SELECT requested_at FROM domain_rate_limits WHERE user_id=?', (user_id,)).fetchone()
        if last and time.time() - last[0] < 30:
            return False
        conn.execute('INSERT INTO domain_rate_limits VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET requested_at=excluded.requested_at', (user_id, int(time.time())))
    return True


def record_report(domain_id, report, only_provider=None):
    with connection() as conn:
        item = conn.execute('SELECT * FROM monitored_domains WHERE id=? AND enabled=1', (domain_id,)).fetchone()
        if not item or item['domain'] != report['domain'] or item['selector'] != report['selector']:
            return None
        cursor = conn.execute('INSERT INTO domain_checks(domain_id,checked_at,status,report) VALUES (?,?,?,?)',
                              (domain_id, report['checked_at'], report['status'], json.dumps(report)))
        check_id = cursor.lastrowid
        settings = provider_settings()
        for result in report['providers']:
            key = result['provider']
            if (only_provider and key != only_provider) or not settings.get(key):
                continue
            active = conn.execute('SELECT id FROM domain_incidents WHERE domain_id=? AND provider=? AND cleared_at IS NULL', (domain_id, key)).fetchone()
            if result['status'] == 'LISTED' and not active:
                incident = conn.execute('INSERT INTO domain_incidents(domain_id,provider,detected_at,detail) VALUES (?,?,?,?)',
                                        (domain_id, key, report['checked_at'], result['detail']))
                if alerts_enabled():
                    conn.execute('INSERT INTO domain_outbox(incident_id,created_at) VALUES (?,?)', (incident.lastrowid, stamp()))
            elif result['status'] == 'CLEAN' and active:
                conn.execute('UPDATE domain_incidents SET cleared_at=? WHERE id=?', (report['checked_at'], active[0]))
        return check_id


def deliver_domain_alerts():
    if not alerts_enabled():
        return
    with connection() as conn:
        rows = conn.execute('''SELECT o.id,i.domain_id,i.provider,i.detected_at,i.detail,m.domain
            FROM domain_outbox o JOIN domain_incidents i ON i.id=o.incident_id
            JOIN monitored_domains m ON m.id=i.domain_id
            WHERE o.sent_at IS NULL AND i.cleared_at IS NULL AND m.enabled=1 ORDER BY o.id LIMIT 30''').fetchall()
    for row in rows:
        if not provider_settings().get(row['provider']):
            continue
        try:
            recipients = parse_recipients(get_setting('alert_recipients', ''))
            if not recipients:
                continue
            send_message(recipients, '[RBL Monitor] Domínio listado: ' + row['domain'],
                         f"Domínio: {row['domain']}\nLista: {PROVIDERS[row['provider']]['name']}\nDetectado UTC: {row['detected_at']}\n{row['detail']}\n")
            with connection() as conn:
                conn.execute('UPDATE domain_outbox SET sent_at=?,attempts=attempts+1,last_error=\'\' WHERE id=?', (stamp(), row['id']))
        except Exception as exc:
            with connection() as conn:
                conn.execute('UPDATE domain_outbox SET attempts=attempts+1,last_error=? WHERE id=?', (type(exc).__name__, row['id']))


def run_domain(domain_id):
    with _lock:
        with connection() as conn:
            item = conn.execute('SELECT * FROM monitored_domains WHERE id=? AND enabled=1', (domain_id,)).fetchone()
        if not item:
            return
        report = analyze(item['domain'], item['selector'])
        result = record_report(domain_id, report)
        deliver_domain_alerts()
        return result


def run_domains():
    with connection() as conn:
        ids = [row[0] for row in conn.execute('SELECT id FROM monitored_domains WHERE enabled=1')]
    for domain_id in ids:
        try:
            run_domain(domain_id)
        except Exception:
            # Do not log resolver exceptions: they can contain DQS credentials.
            import logging
            logging.getLogger(__name__).error('Falha na verificação agendada de domínio id=%s', domain_id)
    with _lock:
        deliver_domain_alerts()


def pending_count():
    with connection() as conn:
        return conn.execute('''SELECT COUNT(*) FROM domain_outbox o
            JOIN domain_incidents i ON i.id=o.incident_id JOIN monitored_domains m ON m.id=i.domain_id
            WHERE o.sent_at IS NULL AND i.cleared_at IS NULL AND m.enabled=1''').fetchone()[0]


def setup_domains(app, factory):
    global _db
    _db = factory
    with connection() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS monitored_domains(
            id INTEGER PRIMARY KEY AUTOINCREMENT,domain TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL DEFAULT '',selector TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS domain_checks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id INTEGER NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
            checked_at TEXT NOT NULL,status TEXT NOT NULL,report TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS domain_check_recent ON domain_checks(domain_id,id DESC);
        CREATE TABLE IF NOT EXISTS domain_incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id INTEGER NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
            provider TEXT NOT NULL,detected_at TEXT NOT NULL,cleared_at TEXT,detail TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS domain_incident_active ON domain_incidents(domain_id,provider) WHERE cleared_at IS NULL;
        CREATE TABLE IF NOT EXISTS domain_outbox(
            id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id INTEGER UNIQUE NOT NULL REFERENCES domain_incidents(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,sent_at TEXT,attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS domain_rate_limits(user_id INTEGER PRIMARY KEY,requested_at INTEGER NOT NULL);
        ''')
    app.register_blueprint(blueprint)


@blueprint.get('/')
def index():
    with connection() as conn:
        rows = conn.execute('''SELECT m.*,c.checked_at,c.status FROM monitored_domains m
            LEFT JOIN domain_checks c ON c.id=(SELECT id FROM domain_checks WHERE domain_id=m.id ORDER BY id DESC LIMIT 1)
            ORDER BY CASE c.status WHEN 'LISTED' THEN 0 WHEN 'ERROR' THEN 1 WHEN 'CLEAN' THEN 2 ELSE 3 END,m.domain''').fetchall()
    return render_template('domains/index.html', rows=rows, report=None, providers=PROVIDERS, configured=provider_settings())


@blueprint.post('/lookup')
def lookup():
    try:
        domain = normalize_domain(request.form.get('domain', ''))
        selector = normalize_selector(request.form.get('selector', ''))
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('domains.index'))
    if not reserve_request(g.user['id']):
        flash('Aguarde 30 segundos entre consultas de domínio.', 'error')
        return redirect(url_for('domains.index'))
    report = analyze(domain, selector)
    return render_template('domains/lookup.html', report=report)


@blueprint.post('/add')
def add():
    try:
        domain = normalize_domain(request.form.get('domain', ''))
        selector = normalize_selector(request.form.get('selector', ''))
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('domains.index'))
    with connection() as conn:
        if conn.execute('SELECT 1 FROM monitored_domains WHERE domain=?', (domain,)).fetchone():
            flash('Domínio já monitorado.', 'error')
        else:
            conn.execute('INSERT INTO monitored_domains(domain,description,selector,created_at) VALUES (?,?,?,?)',
                         (domain, request.form.get('description', '').strip()[:250], selector, stamp()))
            flash('Domínio cadastrado. A consulta ocorrerá no agendamento ou pelo botão Verificar.', 'success')
    return redirect(url_for('domains.index'))


@blueprint.get('/<int:domain_id>')
def detail(domain_id):
    with connection() as conn:
        item = conn.execute('SELECT * FROM monitored_domains WHERE id=?', (domain_id,)).fetchone()
        if not item:
            abort(404)
        total = conn.execute('SELECT COUNT(*) FROM domain_checks WHERE domain_id=?', (domain_id,)).fetchone()[0]
        pages = max(1, (total + 14) // 15)
        page = max(1, min(pages, request.args.get('page', 1, type=int) or 1))
        history = conn.execute('SELECT * FROM domain_checks WHERE domain_id=? ORDER BY id DESC LIMIT 15 OFFSET ?', (domain_id, (page-1)*15)).fetchall()
        selected = request.args.get('check', type=int)
        latest = conn.execute('SELECT report FROM domain_checks WHERE domain_id=? AND id=?', (domain_id, selected)).fetchone() if selected else conn.execute('SELECT report FROM domain_checks WHERE domain_id=? ORDER BY id DESC LIMIT 1', (domain_id,)).fetchone()
        if selected and not latest:
            abort(404)
        incident_total = conn.execute('SELECT COUNT(*) FROM domain_incidents WHERE domain_id=?', (domain_id,)).fetchone()[0]
        incident_pages = max(1, (incident_total + 14) // 15)
        incident_page = max(1, min(incident_pages, request.args.get('incidents', 1, type=int) or 1))
        incidents = conn.execute('SELECT * FROM domain_incidents WHERE domain_id=? ORDER BY id DESC LIMIT 15 OFFSET ?', (domain_id, (incident_page-1)*15)).fetchall()
    return render_template('domains/detail.html', item=item, report=json.loads(latest[0]) if latest else None,
                           history=history, page=page, pages=pages, total=total, incidents=incidents, providers=PROVIDERS,
                           incident_page=incident_page, incident_pages=incident_pages, incident_total=incident_total)


@blueprint.post('/<int:domain_id>/check')
def check(domain_id):
    with connection() as conn:
        item = conn.execute('SELECT enabled FROM monitored_domains WHERE id=?', (domain_id,)).fetchone()
        if not item:
            abort(404)
        if not item['enabled']:
            flash('Domínio desativado.', 'error')
            return redirect(url_for('domains.detail', domain_id=domain_id))
    if not reserve_request(g.user['id']):
        flash('Aguarde 30 segundos entre consultas de domínio.', 'error')
    else:
        run_domain(domain_id)
        flash('Verificação concluída.', 'success')
    return redirect(url_for('domains.detail', domain_id=domain_id))


@blueprint.post('/<int:domain_id>/edit')
def edit(domain_id):
    try:
        selector = normalize_selector(request.form.get('selector', ''))
    except ValueError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('domains.detail', domain_id=domain_id))
    with _lock, connection() as conn:
        if not conn.execute('SELECT 1 FROM monitored_domains WHERE id=?', (domain_id,)).fetchone():
            abort(404)
        conn.execute('UPDATE monitored_domains SET description=?,selector=?,enabled=? WHERE id=?',
                     (request.form.get('description', '').strip()[:250], selector, int('enabled' in request.form), domain_id))
        if 'enabled' not in request.form:
            conn.execute('UPDATE domain_incidents SET cleared_at=? WHERE domain_id=? AND cleared_at IS NULL', (stamp(), domain_id))
            conn.execute('DELETE FROM domain_outbox WHERE sent_at IS NULL AND incident_id IN (SELECT id FROM domain_incidents WHERE domain_id=?)', (domain_id,))
    flash('Configuração do domínio salva.', 'success')
    return redirect(url_for('domains.detail', domain_id=domain_id))


@blueprint.post('/<int:domain_id>/delete')
def delete(domain_id):
    with _lock, connection() as conn:
        conn.execute('DELETE FROM monitored_domains WHERE id=?', (domain_id,))
    flash('Domínio e seu histórico removidos.', 'success')
    return redirect(url_for('domains.index'))


@blueprint.route('/providers', methods=['GET', 'POST'])
@admin_required
def providers():
    if request.method == 'POST':
        selected = {name: name in request.form for name in PROVIDERS}
        if any(selected.values()) and 'access_confirmed' not in request.form:
            flash('Confirme que seu acesso atende às condições dos provedores selecionados.', 'error')
        else:
            with _lock, connection() as conn:
                set_setting(conn, 'domain_providers', json.dumps(selected))
                for name, enabled in selected.items():
                    if not enabled:
                        conn.execute('UPDATE domain_incidents SET cleared_at=? WHERE provider=? AND cleared_at IS NULL', (stamp(), name))
                conn.execute('DELETE FROM domain_outbox WHERE sent_at IS NULL AND incident_id IN (SELECT id FROM domain_incidents WHERE cleared_at IS NOT NULL)')
            flash('Listas de domínio configuradas. Novas consultas usarão esta seleção.', 'success')
            return redirect(url_for('domains.providers'))
    return render_template('domains/providers.html', providers=PROVIDERS, configured=provider_settings())
