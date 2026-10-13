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


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.client = monitor.app.test_client()
        monitor.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        with monitor.db() as conn:
            conn.execute('DELETE FROM monitored_ips')
            conn.execute('DELETE FROM settings')
            cur = conn.execute('INSERT INTO monitored_ips(ip,description,created_at) VALUES (?,?,?)',
                               ('192.0.2.10', 'documentation test', monitor.now()))
            self.ip_id = cur.lastrowid
        conn.close()

    def result(self, status='LISTED'):
        return dict(name='SpamCop', zone='bl.spamcop.net', status=status,
                    response='127.0.0.2', duration_ms=1)

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

    def test_admin_pages_render(self):
        with self.client.session_transaction() as session:
            session['user_id'] = 1
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
        for action in ('ignore', 'unignore', 'dismiss'):
            self.assertEqual(self.client.post(f'/incident/{incident_id}/{action}').status_code, 302)
        with monitor.db() as conn:
            self.assertEqual(conn.execute('SELECT closure_reason FROM incidents').fetchone()[0], 'MANUAL')
        conn.close()


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    gc.collect()
    TEMP.cleanup()
    sys.exit(0 if result.wasSuccessful() else 1)
