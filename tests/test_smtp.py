"""Offline transport and route transaction tests; never connect to real SMTP/SQL."""
import os
import ssl
import smtplib
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import app as dukaan
from tests.test_app import FakeConnection, SequenceCursor


class SMTPTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            'SMTP_HOST': 'smtp.example.test', 'SMTP_FROM': 'sender@example.test',
            'SMTP_USERNAME': 'synthetic-user', 'SMTP_PASSWORD': 'synthetic-password',
            'APP_PUBLIC_URL': 'https://app.example.test',
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.transport = MagicMock()
        self.smtp = self.transport.__enter__.return_value
        self.smtp.ehlo.return_value = (250, b'ready')
        self.smtp.send_message.return_value = {}

    def send(self):
        dukaan.send_invitation_email('recipient@example.test', 'Invitation', 'synthetic-secret-body')

    def assert_verified_context(self, context):
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_starttls_before_auth_and_send_with_explicit_envelope(self):
        with patch.object(smtplib, 'SMTP', return_value=self.transport) as factory, patch.object(smtplib, 'SMTP_SSL') as implicit:
            self.send()
        factory.assert_called_once_with('smtp.example.test', 587, timeout=10)
        implicit.assert_not_called()
        self.assertEqual([call[0] for call in self.smtp.method_calls], ['starttls', 'ehlo', 'login', 'send_message'])
        self.assert_verified_context(self.smtp.starttls.call_args.kwargs['context'])
        self.smtp.login.assert_called_once_with('synthetic-user', 'synthetic-password')
        call = self.smtp.send_message.call_args
        self.assertEqual(call.kwargs, {'from_addr': 'sender@example.test', 'to_addrs': ['recipient@example.test']})
        self.assertEqual(call.args[0]['To'], 'recipient@example.test')
        self.assertEqual(call.args[0].get_content().strip(), 'synthetic-secret-body')

    def test_implicit_tls_and_custom_port_timeout(self):
        for config, port, timeout in [({'SMTP_SECURITY':'ssl'},465,10),
            ({'SMTP_SECURITY':'ssl','SMTP_PORT':'2465','SMTP_TIMEOUT':'20'},2465,20)]:
            with self.subTest(config=config), patch.dict(os.environ, config), \
                 patch.object(smtplib,'SMTP_SSL',return_value=self.transport) as factory, patch.object(smtplib,'SMTP') as plain:
                self.send()
                self.assertEqual(factory.call_args.args,('smtp.example.test',port))
                self.assertEqual(factory.call_args.kwargs['timeout'],timeout)
                self.assert_verified_context(factory.call_args.kwargs['context'])
                plain.assert_not_called()
                self.smtp.starttls.assert_not_called()

    def test_trusted_relay_without_credentials_still_requires_tls(self):
        with patch.dict(os.environ, {'SMTP_USERNAME':'','SMTP_PASSWORD':''}), patch.object(smtplib,'SMTP',return_value=self.transport):
            self.send()
        self.smtp.login.assert_not_called()
        self.smtp.starttls.assert_called_once()

    def test_invalid_configuration_never_connects(self):
        for config in ({'SMTP_HOST':''}, {'SMTP_HOST':'smtp\r\nhost'}, {'SMTP_HOST':'smtp://host'}, {'SMTP_FROM':'Name <sender@example.test>'},
            {'SMTP_FROM':'a@example.test,b@example.test'}, {'SMTP_FROM':'a@example.test\r\nBcc:b@example.test'},
            {'SMTP_SECURITY':'none'}, {'SMTP_PORT':'invalid'}, {'SMTP_PORT':'0'}, {'SMTP_PORT':'65536'},
            {'SMTP_TIMEOUT':'0'}, {'SMTP_TIMEOUT':'61'}, {'SMTP_USERNAME':''}, {'SMTP_PASSWORD':''}):
            with self.subTest(config_keys=list(config)), patch.dict(os.environ,config), \
                 patch.object(smtplib,'SMTP') as smtp, patch.object(smtplib,'SMTP_SSL') as implicit:
                with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                    self.send()
                self.assertEqual(str(raised.exception),'configuration')
                smtp.assert_not_called()
                implicit.assert_not_called()

    def test_invalid_recipient_cannot_expand_delivery(self):
        for recipient in ('a@example.test,b@example.test','A <a@example.test>','a@example.test\r\nBcc:b@example.test'):
            with self.subTest(), patch.object(smtplib,'SMTP') as factory:
                with self.assertRaises(dukaan.EmailDeliveryError):
                    dukaan.send_invitation_email(recipient,'Invitation','body')
                factory.assert_not_called()

    def test_tls_failure_never_authenticates_sends_or_downgrades(self):
        for error in (ssl.SSLCertVerificationError('synthetic-secret'), smtplib.SMTPNotSupportedError('synthetic-secret')):
            with self.subTest(error_type=type(error).__name__), patch.object(smtplib,'SMTP',return_value=self.transport) as factory:
                self.smtp.starttls.side_effect=error
                with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                    self.send()
                self.assertEqual(str(raised.exception),'tls-or-capability')
                self.smtp.login.assert_not_called()
                self.smtp.send_message.assert_not_called()
                factory.assert_called_once()

    def test_auth_refusal_disconnect_and_timeout_are_sanitized(self):
        cases = [('login',smtplib.SMTPAuthenticationError(535,b'synthetic-secret'),'authentication'),
            ('send_message',smtplib.SMTPRecipientsRefused({'recipient@example.test':(550,b'synthetic-secret')}),'rejected'),
            ('send_message',smtplib.SMTPDataError(554,b'synthetic-secret'),'rejected'),
            ('send_message',smtplib.SMTPServerDisconnected('synthetic-secret'),'unavailable'),
            ('send_message',TimeoutError('synthetic-secret'),'timeout')]
        for stage, error, category in cases:
            with self.subTest(stage=stage,category=category), patch.object(smtplib,'SMTP',return_value=self.transport):
                self.smtp.reset_mock(side_effect=True)
                getattr(self.smtp,stage).side_effect=error
                with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                    self.send()
                self.assertEqual(str(raised.exception),category)
                if stage=='login':
                    self.smtp.send_message.assert_not_called()

    def test_refused_mapping_is_not_success(self):
        self.smtp.send_message.return_value={'recipient@example.test':(550,b'synthetic-secret')}
        with patch.object(smtplib,'SMTP',return_value=self.transport):
            with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                self.send()
        self.assertEqual(str(raised.exception),'rejected')

    def test_connection_failure_is_sanitized(self):
        with patch.object(smtplib,'SMTP',side_effect=OSError('synthetic-secret')):
            with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                self.send()
        self.assertEqual(str(raised.exception),'unavailable')

    def test_failed_tls_ehlo_stops_auth_and_message(self):
        self.smtp.ehlo.return_value=(550,b'synthetic-secret')
        with patch.object(smtplib,'SMTP',return_value=self.transport):
            with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                self.send()
        self.assertEqual(str(raised.exception),'unavailable')
        self.smtp.login.assert_not_called()
        self.smtp.send_message.assert_not_called()

    def test_implicit_tls_certificate_failure_never_falls_back(self):
        with patch.dict(os.environ,{'SMTP_SECURITY':'ssl'}), \
             patch.object(smtplib,'SMTP_SSL',side_effect=ssl.SSLCertVerificationError('synthetic-secret')), \
             patch.object(smtplib,'SMTP') as plain:
            with self.assertRaises(dukaan.EmailDeliveryError) as raised:
                self.send()
        self.assertEqual(str(raised.exception),'tls-or-capability')
        plain.assert_not_called()


class SMTPRouteTests(unittest.TestCase):
    def setUp(self):
        dukaan.app.config.update(TESTING=True, SECRET_KEY='smtp-route-test')
        self.client=dukaan.app.test_client()
        self.client.get('/invitations/accept')
        with self.client.session_transaction() as state:
            self.csrf=state['csrf_token']
            state['user']={'global_user_id':1,'organization_id':'11111111-1111-1111-1111-111111111111'}
        self.transport=MagicMock()
        self.smtp=self.transport.__enter__.return_value
        self.smtp.ehlo.return_value=(250,b'ready')
        self.smtp.send_message.return_value={}
        self.env=patch.dict(os.environ, {'SMTP_HOST':'smtp.example.test','SMTP_FROM':'sender@example.test',
                                        'APP_PUBLIC_URL':'https://app.example.test'},clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    @staticmethod
    def authorize():
        dukaan.g.permissions=frozenset({'members.roles'})
        return True

    def create(self, connection):
        with patch.object(dukaan,'resolve_legacy_organization_context',side_effect=self.authorize), \
             patch.object(dukaan,'lock_organization_owner'), patch.object(dukaan,'get_db_connection',return_value=connection), \
             patch.object(smtplib,'SMTP',return_value=self.transport):
            return self.client.post('/organization/invitations',data={'csrf_token':self.csrf,'email':'recipient@example.test','role':'Support'})

    def verification(self, connection):
        with patch.object(dukaan,'lock_organization_owner'), patch.object(dukaan,'get_db_connection',return_value=connection), \
             patch.object(smtplib,'SMTP',return_value=self.transport):
            return self.client.post('/invitations/accept',data={'csrf_token':self.csrf,'action':'verify','token':'x'*43})

    @staticmethod
    def verification_connection():
        invite=SimpleNamespace(Status='Pending',IsExpired=False,OrganizationID='11111111-1111-1111-1111-111111111111',
            CreatedByUserID=1,RoleName='Support',Email='recipient@example.test',RecentlySent=False,InvitationID='22222222-2222-2222-2222-222222222222')
        return FakeConnection(SequenceCursor([SimpleNamespace(OrganizationID=invite.OrganizationID),(invite.OrganizationID,),invite,None]))

    def test_invitation_sent_through_transport_hash_only_persisted(self):
        connection=FakeConnection(SequenceCursor([None,None]))
        response=self.create(connection)
        self.assertEqual(response.status_code,302)
        body=self.smtp.send_message.call_args.args[0].get_content()
        token=body.split('#token=')[1].split()[0]
        self.assertNotIn(token.encode(),response.data)
        inserts=[params for sql,params in connection.cursor_instance.executions if 'INSERT OrganizationInvitations' in sql]
        self.assertEqual(inserts[0][3],dukaan.invitation_digest(token))
        self.assertEqual(connection.commit_count,1)

    def test_verification_sent_only_to_invitee_hash_only_persisted(self):
        connection=self.verification_connection()
        response=self.verification(connection)
        self.assertEqual(response.status_code,200)
        call=self.smtp.send_message.call_args
        code=call.args[0].get_content().splitlines()[1]
        self.assertNotEqual(code,'x'*43)
        self.assertNotIn(code.encode(),response.data)
        self.assertEqual(call.kwargs['to_addrs'],['recipient@example.test'])
        updates=[params for sql,params in connection.cursor_instance.executions if 'SET VerificationHash=' in sql]
        self.assertEqual(updates[0][0],dukaan.invitation_digest(code))
        self.assertEqual(connection.commit_count,1)

    def test_mail_failure_rolls_back_both_routes_without_secret_logging(self):
        for route in ('create','verification'):
            with self.subTest(route=route):
                connection=FakeConnection(SequenceCursor([None,None])) if route=='create' else self.verification_connection()
                self.smtp.send_message.side_effect=smtplib.SMTPDataError(554,b'synthetic-secret-body')
                with self.assertLogs(dukaan.app.logger,level='WARNING') as logs:
                    response=getattr(self,route)(connection)
                self.assertEqual(response.status_code,503)
                self.assertEqual(connection.commit_count,0)
                self.assertEqual(connection.rollback_count,1)
                self.assertTrue(connection.closed)
                self.assertNotIn('synthetic-secret-body',' '.join(logs.output))
                self.assertNotIn(b'synthetic-secret-body',response.data)
                self.assertFalse(any('INSERT OrganizationMemberships' in sql or 'SET VerificationHash=' in sql
                                     for sql,_ in connection.cursor_instance.executions))

    def test_consumed_expired_and_cooldown_invitations_never_send(self):
        for status, expired, recent, expected in [('Accepted',False,False,410),('Revoked',False,False,410),
            ('Expired',False,False,410),('Pending',True,False,410),('Pending',False,True,429)]:
            with self.subTest(status=status,expired=expired,recent=recent):
                connection=self.verification_connection()
                invite=connection.cursor_instance.fetch_results[2]
                invite.Status,invite.IsExpired,invite.RecentlySent=status,expired,recent
                self.assertEqual(self.verification(connection).status_code,expected)
                self.smtp.send_message.assert_not_called()
                self.assertFalse(any('INSERT OrganizationMemberships' in sql for sql,_ in connection.cursor_instance.executions))

    def test_missing_or_wrong_proof_cannot_register_even_with_smtp(self):
        for code in ('','incorrect-proof'):
            with self.subTest(code_present=bool(code)):
                connection=self.verification_connection()
                invite=connection.cursor_instance.fetch_results[2]
                invite.VerificationValid=True
                invite.VerificationHash=dukaan.invitation_digest('other-code')
                with patch.object(dukaan,'lock_organization_owner'), patch.object(dukaan,'get_db_connection',return_value=connection):
                    response=self.client.post('/invitations/accept',data={'csrf_token':self.csrf,'token':'x'*43,
                                                                         'action':'register','verification':code})
                self.assertEqual(response.status_code,403)
                self.assertEqual(connection.commit_count,0)
                self.assertFalse(any('INSERT Users' in sql or 'INSERT OrganizationMemberships' in sql
                                     for sql,_ in connection.cursor_instance.executions))
