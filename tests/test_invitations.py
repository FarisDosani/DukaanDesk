import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import app as dukaan
from tests.test_app import FakeConnection, SequenceCursor


class InvitationTests(unittest.TestCase):
    def setUp(self):
        dukaan.app.config.update(TESTING=True, SECRET_KEY='offline-invitation-test')
        self.client = dukaan.app.test_client()
        self.client.get('/invitations/accept')
        with self.client.session_transaction() as state:
            self.csrf = state['csrf_token']

    def test_public_page_secrets_not_cached_and_csrf_required(self):
        response = self.client.get('/invitations/accept')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn(b'history.replaceState', response.data)
        self.assertEqual(self.client.post('/invitations/accept', data={'token': 'x'*43}).status_code, 400)

    def test_tokens_hashed_and_production_links_use_fixed_https_fragment(self):
        token = dukaan.secrets.token_urlsafe(32)
        self.assertEqual(len(token), 43)
        self.assertEqual(len(dukaan.invitation_digest(token)), 64)
        self.assertNotEqual(token, dukaan.invitation_digest(token))
        with dukaan.app.test_request_context('/'), patch.dict(os.environ, {'APP_PUBLIC_URL':'https://app.example.test'}):
            self.assertEqual(dukaan.invitation_link(token), 'https://app.example.test/invitations/accept#token='+token)
            for origin in ('http://app.example.test', 'https://user:secret@example.test', 'https://example.test/path', ''):
                with self.subTest(origin=origin), patch.dict(os.environ, {'APP_PUBLIC_URL':origin}):
                    with self.assertRaises(ValueError):
                        dukaan.invitation_link(token)

    def test_dev_flow_requires_explicit_development_and_loopback(self):
        for mode, flag, remote, expected in [('development','true','127.0.0.1',True),
            ('production','true','127.0.0.1',False), ('development','false','127.0.0.1',False),
            ('development','true','192.0.2.1',False)]:
            with self.subTest(mode=mode,flag=flag,remote=remote), patch.dict(os.environ, {'APP_ENV':mode,'DEV_INVITATION_LINKS':flag}), \
                 dukaan.app.test_request_context('/', environ_base={'REMOTE_ADDR':remote}):
                self.assertEqual(dukaan.development_invitation_delivery(), expected)

    def test_mail_fails_closed_and_requires_tls(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                dukaan.send_invitation_email('test@example.test','subject','body')
        smtp = MagicMock()
        smtp.__enter__.return_value.ehlo.return_value = (250, b'ready')
        smtp.__enter__.return_value.send_message.return_value = {}
        with patch.dict(os.environ, {'SMTP_HOST':'smtp.example.test','SMTP_FROM':'sender@example.test'}, clear=True), \
             patch.object(dukaan.smtplib,'SMTP',return_value=smtp):
            dukaan.send_invitation_email('test@example.test','subject','body')
            smtp.__enter__.return_value.starttls.assert_called_once()
            smtp.__enter__.return_value.send_message.assert_called_once()

    def test_anonymous_cannot_manage_or_accept_existing_identity(self):
        for path in ('/organization/invitations','/organization/members/1/deactivate',
                     '/organization/invitations/11111111-1111-1111-1111-111111111111/revoke'):
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path,data={'csrf_token':self.csrf}).status_code,302)
        response = self.client.post('/invitations/accept',data={'csrf_token':self.csrf,'action':'accept','token':'x'*43})
        self.assertEqual(response.status_code,403)

    def test_employee_identity_has_no_legacy_id(self):
        row = SimpleNamespace(UserID=None,GlobalUserID=9,Email='e@example.test',Username='employee',
            SellerID=1,OrganizationID='11111111-1111-1111-1111-111111111111',BusinessName='shop',DomainName='shop.test',RoleName='Support')
        with dukaan.app.test_request_context('/dashboard'):
            dukaan.session['user'] = dukaan.build_user_session(dukaan.user_from_membership(row))
            with patch.object(dukaan,'get_db_connection',return_value=FakeConnection(SequenceCursor([row],permissions=['dashboard.view']))):
                self.assertTrue(dukaan.resolve_legacy_organization_context())
            self.assertIsNone(dukaan.session['user']['id'])
            self.assertEqual(dukaan.session['user']['global_user_id'],9)
