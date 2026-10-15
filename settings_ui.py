"""Unified administrator settings: validate everything before one transaction."""
import json
import math
import os
import re

from flask import flash, redirect, render_template, request, url_for

import extensions as ext
import domain_monitor as domains


def validate(form, sources):
    errors, values = [], {}
    if form.get('settings_scope') != 'all':
        raise ValueError('Atualize a página de configurações antes de salvar.')
    try:
        interval = int(form.get('interval', ''))
        timeout = float(form.get('timeout', ''))
        if not 1 <= interval <= 10080 or not math.isfinite(timeout) or not 0.5 <= timeout <= 30:
            raise ValueError()
        values.update(check_interval_minutes=interval, dns_timeout_seconds=timeout)
    except (ValueError, OverflowError):
        errors.append('Tempo de testes: intervalo de 1 a 10080 minutos e timeout de 0,5 a 30 segundos.')

    zones = form.getlist('rbl_zone')
    known = {row['zone'] for row in sources}
    if len(zones) != len(known) or set(zones) != known:
        errors.append('A lista de RBLs mudou. Recarregue a página antes de salvar.')
    updates = {}
    for zone in zones:
        link = form.get('rbl_link:' + zone, '').strip()
        if link and (len(link) > 1000 or not ext.valid_url(link)):
            errors.append('Link de consulta inválido: ' + zone)
        updates[zone] = dict(enabled='rbl_enabled:' + zone in form,
                             supports_ipv6='rbl_ipv6:' + zone in form, link=link)

    # Optional new source participates in this same save, not a second form.
    name, zone = form.get('new_rbl_name', '').strip(), form.get('new_rbl_zone', '').strip().lower().rstrip('.')
    extra = None
    if name or zone:
        if not name or len(name) > 120 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', zone) or len(zone) > 253:
            errors.append('Nova RBL: informe nome e zona DNS válidos.')
        elif zone in known:
            errors.append('A nova zona RBL já existe.')
        else:
            extra = dict(name=name, zone=zone, enabled=False)
    for key, label in (('spamrats_api_key','SpamRATS'), ('spamhaus_dqs_key','Spamhaus DQS')):
        secret = form.get(key, '').strip()
        remove = 'remove_' + key in form
        pattern = r'[A-Za-z0-9]{1,63}' if key == 'spamhaus_dqs_key' else r'[A-Za-z0-9-]{1,63}'
        if (secret and remove) or (secret and not re.fullmatch(pattern, secret)):
            errors.append('Chave ' + label + ' inválida; não preencha e remova ao mesmo tempo.')
        if secret or remove:
            values[key] = '' if remove else secret

    selected = {name: 'domain_' + name in form for name in domains.PROVIDERS}
    if any(selected.values()) and 'domain_access_confirmed' not in form:
        errors.append('Domínios: confirme as condições de acesso às listas selecionadas.')
    values['domain_providers'] = json.dumps(selected)

    host = form.get('smtp_host','').strip()
    sender = form.get('smtp_from','').strip()
    username = form.get('smtp_username','').strip()
    password = form.get('smtp_password','')
    enabled = 'alert_enabled' in form
    remove_password = 'clear_smtp_password' in form
    try:
        port = int(form.get('smtp_port',''))
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        port = 587
        errors.append('SMTP: informe uma porta entre 1 e 65535.')
    if host and (len(host)>253 or any(c.isspace() or ord(c)<33 for c in host) or any(c in host for c in '/\\@#?')):
        errors.append('SMTP: servidor inválido.')
    security = form.get('smtp_security','')
    if security not in {'starttls','ssl','none'}:
        errors.append('SMTP: selecione uma segurança válida.')
    if sender and not ext.valid_email(sender):
        errors.append('SMTP: remetente inválido.')
    if len(username)>254 or any(c in username for c in '\r\n'):
        errors.append('SMTP: usuário inválido.')
    if len(password)>1024 or any(c in password for c in '\r\n') or (password and remove_password):
        errors.append('SMTP: senha inválida; não informe e remova ao mesmo tempo.')
    try:
        recipients = ext.parse_recipients(form.get('recipients',''))
    except ValueError as exc:
        recipients = []
        errors.append(str(exc))
    if enabled and (not host or not sender or not recipients):
        errors.append('SMTP: alertas ativos exigem servidor, remetente e destinatários.')
    values.update(smtp_host=host, smtp_port=port, smtp_security=security, smtp_username=username,
                  smtp_from=sender, alert_recipients=', '.join(recipients), alert_enabled='1' if enabled else '0')
    if password or remove_password:
        values['smtp_password'] = '' if remove_password else password
    if errors:
        raise ValueError('\n'.join(errors))
    return values, updates, selected, extra


def page(factory, config):
    sources = ext.effective_rbls()
    if request.method == 'POST':
        try:
            values, updates, selected, extra = validate(request.form, sources)
        except ValueError as exc:
            for error in str(exc).splitlines():
                flash(error, 'error')
            # Keep non-secret edits for correction; password inputs always blank.
        else:
            with domains._lock:
                conn = factory()
                try:
                    conn.execute('BEGIN IMMEDIATE')
                    def saved(key, default):
                        row = conn.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone()
                        return json.loads(row[0]) if row else default
                    overrides = saved('rbl_overrides', {})
                    for zone, update in updates.items():
                        overrides[zone] = {**overrides.get(zone, {}), 'enabled':update['enabled'],
                                           'supports_ipv6':update['supports_ipv6']}
                        ext.set_setting(conn,'delisting:'+zone,update['link'])
                    values['rbl_overrides'] = json.dumps(overrides)
                    if extra:
                        extras = saved('extra_rbls', [])
                        if any(row['zone'] == extra['zone'] for row in extras):
                            raise ValueError('A lista de RBLs mudou. Recarregue a página.')
                        extras.append(extra)
                        values['extra_rbls'] = json.dumps(extras)
                    for key, value in values.items():
                        ext.set_setting(conn,key,value)
                    ext.close_disabled_incidents(conn)
                    for key, enabled in selected.items():
                        if not enabled:
                            conn.execute('UPDATE domain_incidents SET cleared_at=? WHERE provider=? AND cleared_at IS NULL',
                                         (domains.stamp(),key))
                    conn.execute('DELETE FROM domain_outbox WHERE sent_at IS NULL AND incident_id IN (SELECT id FROM domain_incidents WHERE cleared_at IS NOT NULL)')
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
            ext.schedule_changed.set()
            flash('Todas as configurações foram salvas.', 'success')
            return redirect(url_for('settings'))
    smtp = ext.smtp_config()
    return render_template('settings_all.html', rbls=sources, smtp={k:v for k,v in smtp.items() if k!='password'},
        password_configured=bool(smtp['password']), alerts_active=ext.alerts_enabled(),
        recipients=ext.get_setting('alert_recipients'), providers=domains.PROVIDERS,
        configured=domains.provider_settings(), form=request.form if request.method=='POST' else None,
        interval=ext.get_setting('check_interval_minutes', int(float(config.get('check_interval_hours',24))*60)),
        timeout=ext.get_setting('dns_timeout_seconds', config.get('dns_timeout_seconds',4)),
        spamrats_configured=bool(ext.get_setting('spamrats_api_key',os.getenv('SPAMRATS_API_KEY',''))),
        spamhaus_configured=bool(ext.get_setting('spamhaus_dqs_key',os.getenv('SPAMHAUS_DQS_KEY',''))))
