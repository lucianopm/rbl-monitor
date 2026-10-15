"""Offline regression tests: isolated SQLite, mocked DNS and SMTP."""
import os
import gc
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TEMP = tempfile.TemporaryDirectory()
os.environ.update(RBL_MONITOR_DB=str(Path(TEMP.name) / 'test.db'),
                  ENABLE_SCHEDULER='0', ADMIN_PASSWORD='offline-test-password',
                  RBL_MONITOR_SECRET='test-only-session-secret-do-not-deploy')
import app as monitor
import extensions as ext
import domain_monitor as domains


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.client = monitor.app.test_client()
        monitor.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        with monitor.db() as conn:
            conn.execute('DELETE FROM users WHERE id<>1')
            conn.execute("UPDATE users SET active=1,is_admin=1 WHERE id=1")
            conn.execute('DELETE FROM monitored_ips')
            conn.execute('DELETE FROM settings')
            conn.execute('DELETE FROM monitored_domains')
            conn.execute('DELETE FROM domain_rate_limits')
            cur = conn.execute('INSERT INTO monitored_ips(ip,description,created_at) VALUES (?,?,?)',
                               ('192.0.2.10', 'documentation test', monitor.now()))
            self.ip_id = cur.lastrowid
        conn.close()

    def result(self, status='LISTED'):
        return dict(name='SpamCop', zone='bl.spamcop.net', status=status,
                    response='127.0.0.2', duration_ms=1)

    def authenticate_as(self, client, user_id):
        with monitor.db() as conn:
            token = conn.execute('SELECT session_token FROM users WHERE id=?', (user_id,)).fetchone()[0]
        conn.close()
        with client.session_transaction() as session:
            session['user_id'] = user_id
            session['user_token'] = token

    def add_test_user(self, admin=False):
        from werkzeug.security import generate_password_hash
        import secrets
        with monitor.db() as conn:
            cursor = conn.execute('INSERT INTO users(username,password_hash,is_admin,session_token) VALUES (?,?,?,?)',
                                  ('other', generate_password_hash('other-test-password'), int(admin), secrets.token_hex(32)))
            user_id = cursor.lastrowid
        conn.close()
        return user_id

    def test_admin_role_change_revokes_sessions(self):
        user_id = self.add_test_user(admin=True)
        other_client = monitor.app.test_client()
        self.authenticate_as(other_client, user_id)
        self.authenticate_as(self.client, 1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        self.assertEqual(self.client.post(f'/admin/users/{user_id}/role', data={'role':'operator'}).status_code, 302)
        self.assertEqual(other_client.get('/admin/settings').status_code, 302)
        self.authenticate_as(other_client, user_id)
        self.assertEqual(other_client.get('/admin/settings').status_code, 403)
        self.assertEqual(other_client.post('/admin/users/1/delete').status_code, 403)

    def test_login_sets_revocable_session(self):
        from werkzeug.security import generate_password_hash
        with monitor.db() as conn:
            conn.execute('UPDATE users SET password_hash=? WHERE id=1', (generate_password_hash('login-test-password'),))
        conn.close()
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        response = self.client.post('/login', data={'username':'admin','password':'login-test-password'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/admin/users').status_code, 200)
        with self.client.session_transaction() as session:
            self.assertTrue(session.get('user_token'))
        with monitor.db() as conn:
            conn.execute("UPDATE users SET session_token='changed-test-token' WHERE id=1")
        conn.close()
        self.assertEqual(self.client.get('/admin/users').status_code, 302)

    def test_deactivate_reactivate_does_not_restore_old_session(self):
        user_id = self.add_test_user()
        other_client = monitor.app.test_client()
        self.authenticate_as(other_client, user_id)
        self.authenticate_as(self.client, 1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        self.client.post(f'/admin/users/{user_id}/toggle')
        self.assertEqual(other_client.get('/account').status_code, 302)
        self.client.post(f'/admin/users/{user_id}/toggle')
        self.assertEqual(other_client.get('/account').status_code, 302)
        self.assertEqual(self.client.post('/admin/users/99999/delete').status_code, 404)

    def test_admin_password_reset_validates_and_revokes(self):
        from werkzeug.security import check_password_hash
        user_id = self.add_test_user()
        other_client = monitor.app.test_client()
        self.authenticate_as(other_client, user_id)
        self.authenticate_as(self.client, 1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        self.client.post(f'/admin/users/{user_id}/password', data={'password':'new-test-password', 'password_confirm':'different'})
        self.assertEqual(other_client.get('/account').status_code, 200)
        self.client.post(f'/admin/users/{user_id}/password', data={'password':'new-test-password', 'password_confirm':'new-test-password'})
        self.assertEqual(other_client.get('/account').status_code, 302)
        with monitor.db() as conn:
            hashed = conn.execute('SELECT password_hash FROM users WHERE id=?', (user_id,)).fetchone()[0]
            self.assertTrue(check_password_hash(hashed, 'new-test-password'))
        conn.close()

    def test_delete_user_preserves_ips_and_prevents_session_id_reuse(self):
        user_id = self.add_test_user()
        other_client = monitor.app.test_client()
        self.authenticate_as(other_client, user_id)
        self.authenticate_as(self.client, 1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        self.assertEqual(self.client.post(f'/admin/users/{user_id}/delete').status_code, 302)
        replacement = self.add_test_user()
        self.assertEqual(replacement, user_id)
        self.assertEqual(other_client.get('/account').status_code, 302)
        with monitor.db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM monitored_ips').fetchone()[0], 1)
        conn.close()

    def test_admin_self_actions_blocked_and_csrf_required(self):
        self.authenticate_as(self.client, 1)
        for action in ('role', 'password', 'toggle', 'delete'):
            self.assertEqual(self.client.post(f'/admin/users/1/{action}').status_code, 400)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        for action in ('role', 'password', 'toggle', 'delete'):
            self.client.post(f'/admin/users/1/{action}', data={'role':'operator'})
        with monitor.db() as conn:
            row = conn.execute('SELECT active,is_admin FROM users WHERE id=1').fetchone()
            self.assertEqual(tuple(row), (1,1))
        conn.close()

    def test_public_and_protected_routes(self):
        for url in ('/', '/login', '/health', f'/ip/{self.ip_id}'):
            self.assertEqual(self.client.get(url).status_code, 200, url)
        self.assertEqual(self.client.get('/admin/smtp').status_code, 302)

    def test_csrf_enforced(self):
        self.assertEqual(self.client.post(f'/ip/{self.ip_id}/check').status_code, 400)

    def test_dashboard_counts_errors_even_when_listed(self):
        from flask import template_rendered
        captured = []
        def capture(sender, template, context, **extra):
            captured.append(context)
        with monitor.db() as conn:
            conn.execute('INSERT INTO checks(ip_id,checked_at,status,error_count) VALUES (?,?,?,1)',
                         (self.ip_id, monitor.now(), 'LISTED'))
            ext.record_incidents(conn, self.ip_id, monitor.now(), [self.result()])
        conn.close()
        with template_rendered.connected_to(capture, monitor.app):
            self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(captured[0]['stats']['errors'], 1)
        self.assertEqual(captured[0]['stats']['listed'], 1)
        self.assertEqual(captured[0]['stats']['clean'], 0)

    def test_dashboard_counts_identity_failure(self):
        with monitor.db() as conn:
            cur = conn.execute('INSERT INTO checks(ip_id,checked_at,status) VALUES (?,?,?)',
                               (self.ip_id, monitor.now(), 'CLEAN'))
            conn.execute('INSERT INTO dns_identity_results(check_id,rdns_status,fcrdns_status) VALUES (?,?,?)',
                         (cur.lastrowid, 'PASS', 'FAIL'))
        conn.close()
        html = self.client.get('/').get_data(as_text=True)
        self.assertIn('data-error="1"', html)
        self.assertIn('data-healthy="0"', html)

    def test_all_templates_compile(self):
        for name in monitor.app.jinja_env.list_templates():
            monitor.app.jinja_env.get_template(name)

    def test_footer_version_and_safe_build_metadata(self):
        from version_info import build_label
        html = self.client.get('/login').get_data(as_text=True)
        self.assertIn('v' + (ROOT / 'VERSION').read_text().strip(), html)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'VERSION').write_text('1.3.0-dev', encoding='utf-8')
            (base / '.git-version').write_text('abcdef1234567890', encoding='utf-8')
            (base / '.git-channel').write_text('dev', encoding='utf-8')
            self.assertEqual(build_label(base), 'v1.3.0-dev · dev · abcdef123456')
            (base / 'VERSION').write_text('<script>invalid</script>', encoding='utf-8')
            self.assertNotIn('<script>', build_label(base))

    def test_cli_password_reset_preserves_data(self):
        import importlib.util
        from werkzeug.security import check_password_hash
        spec = importlib.util.spec_from_file_location('password_reset', ROOT / 'reset-admin-password.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.reset_password(monitor.DB_PATH, 'admin', 'new-test-password-only')
        with monitor.db() as conn:
            hashed = conn.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()[0]
            self.assertTrue(check_password_hash(hashed, 'new-test-password-only'))
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM monitored_ips').fetchone()[0], 1)
        conn.close()
        with self.assertRaises(ValueError):
            module.reset_password(monitor.DB_PATH, 'missing-user', 'new-test-password-only')

    def test_independent_event_pagination_keeps_latest_results(self):
        from flask import template_rendered
        captured = []
        def capture(sender, template, context, **extra):
            captured.append(context)
        with monitor.db() as conn:
            for _ in range(31):
                conn.execute('INSERT INTO checks(ip_id,checked_at,status) VALUES (?,?,?)',
                             (self.ip_id, monitor.now(), 'CLEAN'))
                conn.execute('INSERT INTO incidents(ip_id,rbl_zone,rbl_name,detected_at,last_seen_at,cleared_at) VALUES (?,?,?,?,?,?)',
                             (self.ip_id, 'bl.spamcop.net', 'Test', monitor.now(), monitor.now(), monitor.now()))
            latest = conn.execute('SELECT MAX(id) FROM checks').fetchone()[0]
        conn.close()
        with template_rendered.connected_to(capture, monitor.app):
            response = self.client.get(f'/ip/{self.ip_id}?history_page=2&incident_page=3&expand=history')
        self.assertEqual(response.status_code, 200)
        context = captured[0]
        self.assertEqual(len(context['checks']), 15)
        self.assertEqual(len(context['incidents']), 1)
        self.assertEqual(context['last']['id'], latest)
        self.assertEqual(context['history_pager']['pages'], 3)
        self.assertIn('id="history" open', response.get_data(as_text=True))
        html = self.client.get(f'/ip/{self.ip_id}').get_data(as_text=True)
        self.assertNotIn('id="history" open', html)
        self.assertNotIn('id="incidents" open', html)

    def test_admin_pages_render(self):
        with self.client.session_transaction() as session:
            session['user_id'] = 1
            with monitor.db() as conn:
                session['user_token'] = conn.execute('SELECT session_token FROM users WHERE id=1').fetchone()[0]
            conn.close()
        for url in ('/admin/smtp', '/admin/rbls', '/admin/users', '/admin/settings', '/account'):
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_dnsbl_clean_listed_timeout(self):
        import dns.resolver
        import dns.exception
        with patch('app.dns.resolver.Resolver') as resolver:
            resolver.return_value.resolve.return_value = ['127.0.0.2']
            self.assertEqual(monitor.check_one_rbl('192.0.2.10', self.result())['status'], 'LISTED')
            resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()
            self.assertEqual(monitor.check_one_rbl('192.0.2.10', self.result())['status'], 'CLEAN')
            resolver.return_value.resolve.side_effect = dns.exception.Timeout()
            self.assertEqual(monitor.check_one_rbl('192.0.2.10', self.result())['status'], 'TIMEOUT')

    def test_spamhaus_access_error_not_listed(self):
        with patch('app.dns.resolver.Resolver') as resolver:
            resolver.return_value.resolve.return_value = ['127.255.255.254']
            result = monitor.check_one_rbl('192.0.2.10', dict(name='ZEN', zone='zen.spamhaus.org'))
            self.assertEqual(result['status'], 'DNS_ERROR')

    def test_rdns_fcrdns(self):
        with patch('app.dns.resolver.Resolver') as resolver:
            resolver.return_value.resolve.side_effect = [[SimpleNamespace(target='mail.example.com.')], ['192.0.2.10']]
            result = monitor.check_dns_identity('192.0.2.10')
            self.assertEqual((result['rdns_status'], result['fcrdns_status']), ('PASS', 'PASS'))

    def test_dns_error_preserves_incident(self):
        with monitor.db() as conn:
            ext.record_incidents(conn, self.ip_id, monitor.now(), [self.result()])
            ext.record_incidents(conn, self.ip_id, monitor.now(), [self.result('TIMEOUT')])
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM incidents WHERE cleared_at IS NULL').fetchone()[0], 1)
            ext.record_incidents(conn, self.ip_id, monitor.now(), [self.result('CLEAN')])
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM incidents WHERE cleared_at IS NULL').fetchone()[0], 0)
        conn.close()

    def test_disabled_and_ignore_suppress_alerts(self):
        with monitor.db() as conn:
            ext.set_setting(conn, 'alert_enabled', '1')
            ext.set_setting(conn, 'alert_recipients', 'test@example.com')
            conn.execute('INSERT INTO incident_ignores VALUES (?,?,?,?)',
                         (self.ip_id, 'bl.spamcop.net', monitor.now(), 'test'))
            ext.record_incidents(conn, self.ip_id, monitor.now(), [self.result()])
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM alert_outbox').fetchone()[0], 0)
            ext.set_setting(conn, 'rbl_overrides', '{"bl.spamcop.net":{"enabled":false}}')
            ext.close_disabled_incidents(conn)
            self.assertEqual(conn.execute('SELECT closure_reason FROM incidents').fetchone()[0], 'DISABLED')
        conn.close()

    def test_retry_only_target_and_preserves_other_timestamp(self):
        with monitor.db() as conn:
            cur = conn.execute('INSERT INTO checks(ip_id,checked_at,status,total_rbls,error_count) VALUES (?,?,?,2,1)',
                               (self.ip_id, '2026-01-01 00:00:00', 'ERROR'))
            check_id = cur.lastrowid
            cur = conn.execute('INSERT INTO results(check_id,rbl_name,rbl_zone,status,checked_at) VALUES (?,?,?,?,?)',
                               (check_id, 'SpamCop', 'bl.spamcop.net', 'TIMEOUT', '2026-01-01 00:00:00'))
            target_id = cur.lastrowid
            conn.execute('INSERT INTO results(check_id,rbl_name,rbl_zone,status,checked_at) VALUES (?,?,?,?,?)',
                         (check_id, 'ZEN', 'zen.spamhaus.org', 'CLEAN', '2026-01-01 00:00:00'))
        conn.close()
        with patch('app.check_one_rbl', return_value=self.result('CLEAN')) as query, patch('app.deliver_alerts'):
            new_id = monitor.retry_one_rbl(self.ip_id, target_id)
            query.assert_called_once()
            self.assertEqual(query.call_args.args[1]['zone'], 'bl.spamcop.net')
        with monitor.db() as conn:
            self.assertEqual(conn.execute('SELECT check_type FROM checks WHERE id=?', (new_id,)).fetchone()[0], 'RETRY')
            self.assertEqual(conn.execute('SELECT checked_at FROM results WHERE check_id=? AND rbl_zone=?',
                                         (new_id, 'zen.spamhaus.org')).fetchone()[0], '2026-01-01 00:00:00')
        conn.close()

    def test_health_detects_database_failure(self):
        with patch('extensions._db', side_effect=RuntimeError('test')):
            self.assertEqual(self.client.get('/health').status_code, 503)

    def test_brazilian_time(self):
        self.assertEqual(monitor.br_datetime('2026-01-01 03:00:00'), '01/01/2026 00:00:00')

    def test_smtp_starttls_before_authentication(self):
        configuration = dict(host='smtp.example.com', port=587, security='starttls',
                             username='test', password='test-only', sender='monitor@example.com')
        with patch('extensions.smtp_config', return_value=configuration), patch('extensions.smtplib.SMTP') as factory:
            ext.send_message(['test@example.com'], 'Test', 'Offline message')
            smtp = factory.return_value.__enter__.return_value
            self.assertEqual([call[0] for call in smtp.method_calls],
                             ['ehlo', 'starttls', 'ehlo', 'login', 'send_message'])

    def test_ignore_dismiss_and_unignore_routes(self):
        with monitor.db() as conn:
            ext.record_incidents(conn, self.ip_id, monitor.now(), [self.result()])
            incident_id = conn.execute('SELECT id FROM incidents').fetchone()[0]
        conn.close()
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        with self.client.session_transaction() as session:
            session['user_id'] = 1
            with monitor.db() as conn:
                session['user_token'] = conn.execute('SELECT session_token FROM users WHERE id=1').fetchone()[0]
            conn.close()
        for action in ('ignore', 'unignore', 'dismiss'):
            self.assertEqual(self.client.post(f'/incident/{incident_id}/{action}').status_code, 302)
        with monitor.db() as conn:
            self.assertEqual(conn.execute('SELECT closure_reason FROM incidents').fetchone()[0], 'MANUAL')
        conn.close()


def domain_report(status='LISTED'):
    return dict(domain='example.com', selector='', checked_at=domains.stamp(), status=status,
                listed_count=int(status == 'LISTED'), error_count=int(status == 'ERROR'), auth={},
                providers=[dict(provider='uribl', name='URIBL MULTI', domain='example.com',
                                status=status, detail='Offline fixture')])


class DomainFeatureTests(unittest.TestCase):
    setUp = MonitorTests.setUp
    authenticate_as = MonitorTests.authenticate_as
    add_test_user = MonitorTests.add_test_user

    def enroll(self):
        with domains.connection() as conn:
            ext.set_setting(conn, 'domain_providers', '{"uribl":true}')
            cursor = conn.execute('INSERT INTO monitored_domains(domain,created_at) VALUES (?,?)',
                                  ('example.com', domains.stamp()))
            return cursor.lastrowid

    def test_normalization(self):
        self.assertEqual(domains.normalize_domain('WWW.Example.COM.'), 'www.example.com')
        self.assertEqual(domains.normalize_domain('exemplo.com.br'), 'exemplo.com.br')
        self.assertTrue(domains.normalize_domain('café.com').startswith('xn--'))
        for value in ('127.0.0.1', 'https://example.com', 'user@example.com', 'example.com:80', 'localhost', 'com.br'):
            with self.assertRaises(ValueError):
                domains.normalize_domain(value)
        with self.assertRaises(ValueError):
            domains.normalize_selector('selector..bad')

    def test_code_classification(self):
        for provider, code in (('dbl','127.0.1.255'), ('uribl','127.0.0.1'), ('surbl','127.0.0.1')):
            self.assertEqual(domains.classify_codes(provider, [code])[0], 'DNS_ERROR')
        self.assertEqual(domains.classify_codes('uribl', ['127.0.0.2'])[0], 'LISTED')
        self.assertEqual(domains.classify_codes('uribl', ['127.0.0.8'])[0], 'NOTICE')
        self.assertEqual(domains.classify_codes('surbl', ['127.0.0.16'])[0], 'LISTED')
        self.assertEqual(domains.classify_codes('surbl', ['127.0.0.32'])[0], 'NOTICE')

    def test_access_failure_is_not_clean(self):
        with patch.object(domains, 'query', return_value=('NXDOMAIN', [])) as query:
            result = domains.check_provider('example.com', 'uribl', {'uribl':True})
        self.assertEqual(result['status'], 'ACCESS_ERROR')
        self.assertEqual(query.call_count, 1)

    def test_positive_test_then_clean_registrable_target(self):
        with patch.object(domains, 'query', side_effect=[('ANSWER',['127.0.0.14']), ('NXDOMAIN',[])]) as query:
            result = domains.check_provider('mail.example.com.br', 'uribl', {'uribl':True})
        self.assertEqual(result['status'], 'CLEAN')
        self.assertEqual(query.call_args.args[0], 'example.com.br.multi.uribl.com')

    def test_default_disabled(self):
        with patch.object(domains, 'query') as query:
            self.assertEqual(domains.check_provider('example.com','dbl',{})['status'], 'DISABLED')
        query.assert_not_called()

    def test_resolver_failure_sanitized(self):
        with patch.object(domains.dns.resolver, 'Resolver', side_effect=RuntimeError('secret')):
            self.assertEqual(domains.query('example.com','TXT'), ('DNS_ERROR', []))

    def test_dmarc_error_not_inherited(self):
        with patch.object(domains, 'query', side_effect=[('NXDOMAIN',[]),('TIMEOUT',[]),('NXDOMAIN',[])]) as query:
            result = domains.check_auth('mail.example.com','')
        self.assertEqual(result['DMARC']['status'], 'TIMEOUT')
        self.assertEqual(result['DKIM']['status'], 'NOT_CHECKED')
        self.assertEqual(query.call_count, 3)

    def test_dmarc_inheritance(self):
        with patch.object(domains, 'query', side_effect=[('NXDOMAIN',[]),('NXDOMAIN',[]),
                    ('ANSWER',['v=DMARC1; p=reject; sp=quarantine']),('NXDOMAIN',[])]):
            result = domains.check_auth('mail.example.com','')
        self.assertIn('quarantine', result['DMARC']['detail'])
        self.assertIn('herdada', result['DMARC']['detail'])

    def test_lookup_ephemeral_rate_and_no_cache(self):
        self.authenticate_as(self.client, 1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        with patch.object(domains, 'analyze', return_value=domain_report()) as analyze:
            response = self.client.post('/domains/lookup', data={'domain':'example.com'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertEqual(self.client.post('/domains/lookup', data={'domain':'example.com'}).status_code, 302)
            self.assertEqual(analyze.call_count, 1)
        with domains.connection() as conn:
            for table in ('monitored_domains','domain_checks','domain_incidents','domain_outbox'):
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0], 0)

    def test_permissions_and_csrf(self):
        self.assertEqual(self.client.get('/domains/').status_code, 302)
        self.authenticate_as(self.client, self.add_test_user())
        self.assertEqual(self.client.get('/domains/').status_code, 200)
        self.assertEqual(self.client.get('/domains/providers').status_code, 403)
        self.assertEqual(self.client.post('/domains/add', data={'domain':'example.com'}).status_code, 400)

    def test_incident_lifecycle_errors_preserve(self):
        domain_id = self.enroll()
        with patch.object(domains, 'alerts_enabled', return_value=True):
            domains.record_report(domain_id, domain_report())
            domains.record_report(domain_id, domain_report())
            domains.record_report(domain_id, domain_report('ERROR'))
        with domains.connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM domain_incidents WHERE cleared_at IS NULL').fetchone()[0],1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM domain_outbox').fetchone()[0],1)
        domains.record_report(domain_id, domain_report('CLEAN'))
        self.assertEqual(domains.pending_count(), 0)

    def test_monitor_history_delete_and_pause(self):
        domain_id = self.enroll()
        for _ in range(17):
            domains.record_report(domain_id, domain_report('CLEAN'))
        self.authenticate_as(self.client,1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        self.assertEqual(self.client.get(f'/domains/{domain_id}?page=2').status_code,200)
        self.client.post(f'/domains/{domain_id}/edit', data={'description':'Paused'})
        with patch.object(domains, 'analyze') as analyze:
            domains.run_domains()
            analyze.assert_not_called()
        self.client.post(f'/domains/{domain_id}/delete')
        with domains.connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM domain_checks').fetchone()[0],0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM monitored_ips').fetchone()[0],1)

    def test_dqs_key_not_in_report(self):
        import json
        with patch.object(monitor, 'provider_key', return_value='privateTestToken'), patch.object(domains, 'query',
                side_effect=[('ANSWER',['127.0.1.2']), ('ANSWER',['127.255.255.250'])]):
            result = domains.check_provider('example.com','dbl',{'dbl':True})
        self.assertEqual(result['status'], 'DNS_ERROR')
        self.assertNotIn('privateTestToken', json.dumps(result))

    def test_provider_settings_and_disabled_pending(self):
        domain_id = self.enroll()
        with patch.object(domains, 'alerts_enabled', return_value=True):
            domains.record_report(domain_id, domain_report())
        self.authenticate_as(self.client,1)
        monitor.app.config['WTF_CSRF_ENABLED'] = False
        self.assertEqual(self.client.get('/domains/providers').status_code,200)
        self.client.post('/domains/providers', data={'dbl':'on'})
        self.assertFalse(domains.provider_settings().get('dbl'))
        self.client.post('/domains/providers', data={})
        self.assertEqual(domains.pending_count(),0)
        with domains.connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM domain_outbox').fetchone()[0],0)

    def test_smtp_delivery_once_and_error_redaction(self):
        domain_id = self.enroll()
        with domains.connection() as conn:
            ext.set_setting(conn,'alert_recipients','admin@example.com')
        with patch.object(domains,'alerts_enabled',return_value=True):
            domains.record_report(domain_id, domain_report())
            with patch.object(domains,'send_message',side_effect=RuntimeError('secret credentials')):
                domains.deliver_domain_alerts()
            with domains.connection() as conn:
                self.assertEqual(conn.execute('SELECT last_error FROM domain_outbox').fetchone()[0],'RuntimeError')
            with patch.object(domains,'send_message') as send:
                domains.deliver_domain_alerts()
                domains.deliver_domain_alerts()
                send.assert_called_once()

    def test_snapshot_scope_and_independent_pagination(self):
        domain_id = self.enroll()
        first = domains.record_report(domain_id, domain_report('CLEAN'))
        for _ in range(16):
            domains.record_report(domain_id, domain_report('ERROR'))
        self.authenticate_as(self.client,1)
        response = self.client.get(f'/domains/{domain_id}?check={first}&page=2&incidents=1')
        self.assertEqual(response.status_code,200)
        self.assertIn(b'CLEAN',response.data)
        self.assertEqual(self.client.get(f'/domains/{domain_id}?check=99999').status_code,404)

    def test_templates_compile_and_scheduler_selects_enabled(self):
        for name in monitor.app.jinja_env.list_templates():
            monitor.app.jinja_env.get_template(name)
        domain_id = self.enroll()
        with patch.object(domains,'run_domain') as run, patch.object(domains,'deliver_domain_alerts'):
            domains.run_domains()
            run.assert_called_once_with(domain_id)


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    gc.collect()
    TEMP.cleanup()
    sys.exit(0 if result.wasSuccessful() else 1)
