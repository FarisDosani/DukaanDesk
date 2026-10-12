import os
import unittest
import uuid
import re
from unittest.mock import patch
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import app as dukaan


RUN_SQL_INTEGRATION = (
    os.getenv("RUN_SQL_INTEGRATION_TESTS") == "1"
    and os.getenv("DB_NAME") == "DukaanDesk_Test"
)


@unittest.skipUnless(
    RUN_SQL_INTEGRATION,
    "requires RUN_SQL_INTEGRATION_TESTS=1 and DB_NAME=DukaanDesk_Test",
)
class SQLIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dukaan.app.config.update(TESTING=True, SECRET_KEY="sql-integration-test-only")
        cls.connection = dukaan.get_db_connection()
        database_name = cls.connection.cursor().execute("SELECT DB_NAME()").fetchone()[0]
        if database_name != "DukaanDesk_Test":
            cls.connection.close()
            raise RuntimeError("Refusing to test outside DukaanDesk_Test")
        cls.original_rows = cls.snapshot_legacy()
        cls.original_identity_rows = {}
        for table in ("Users", "OrganizationMemberships"):
            if cls.connection.cursor().execute("SELECT OBJECT_ID(?, 'U')", (f"dbo.{table}",)).fetchone()[0]:
                columns = 'UserID, OrganizationID, Status, CreatedAt' if table == 'OrganizationMemberships' else '*'
                cls.original_identity_rows[table] = {tuple(row) for row in cls.connection.cursor().execute(f"SELECT {columns} FROM dbo.{table}").fetchall()}
        cls.original_roles = set()
        cls.original_invitations = set()
        if cls.connection.cursor().execute("SELECT OBJECT_ID('dbo.OrganizationInvitations','U')").fetchone()[0]:
            cls.original_invitations = {tuple(row) for row in cls.connection.cursor().execute('SELECT * FROM OrganizationInvitations').fetchall()}
        if cls.connection.cursor().execute("SELECT COL_LENGTH('dbo.OrganizationMemberships','RoleName')").fetchone()[0]:
            cls.original_roles = {tuple(row) for row in cls.connection.cursor().execute('SELECT UserID,OrganizationID,RoleName FROM OrganizationMemberships').fetchall()}

    @classmethod
    def tearDownClass(cls):
        try:
            current = cls.snapshot_legacy()
            if not all(set(rows).issubset(set(current[table])) for table, rows in cls.original_rows.items()):
                raise AssertionError("Pre-existing legacy rows changed during integration verification")
            for table, rows in cls.original_identity_rows.items():
                columns = 'UserID, OrganizationID, Status, CreatedAt' if table == 'OrganizationMemberships' else '*'
                current_rows = {tuple(row) for row in cls.connection.cursor().execute(f"SELECT {columns} FROM dbo.{table}").fetchall()}
                if not rows.issubset(current_rows):
                    raise AssertionError("Pre-existing identity rows changed during integration verification")
            current_roles = {tuple(row) for row in cls.connection.cursor().execute('SELECT UserID,OrganizationID,RoleName FROM OrganizationMemberships').fetchall()}
            if not cls.original_roles.issubset(current_roles):
                raise AssertionError('Pre-existing role assignments changed')
            if cls.original_invitations:
                invitations = {tuple(row) for row in cls.connection.cursor().execute('SELECT * FROM OrganizationInvitations').fetchall()}
                if not cls.original_invitations.issubset(invitations):
                    raise AssertionError('Pre-existing invitations changed')
        finally:
            cls.connection.close()

    @classmethod
    def snapshot_legacy(cls):
        # Full values stay in memory; never print credential material on assertion failure.
        return {table: [tuple(row) for row in cls.connection.cursor().execute(f"SELECT * FROM dbo.{table}").fetchall()]
                for table in ("Sellers", "ClientUsers", "Organizations", "Buyers", "Orders", "MessageLogs")}

    def apply_identity_migration(self):
        self.assertEqual(self.query_one("SELECT DB_NAME()")[0], "DukaanDesk_Test")
        sql = (Path(__file__).parents[1] / "7_UsersMemberships.sql").read_text(encoding="utf-8")
        self.connection.cursor().execute(sql)
        self.connection.commit()

    def test_00_identity_migration_preserves_data_and_is_idempotent(self):
        before = self.snapshot_legacy()
        mapped_ids = set()
        if self.query_one("SELECT OBJECT_ID('dbo.Users','U')")[0] is not None:
            mapped_ids = {row[0] for row in self.connection.cursor().execute("SELECT LegacyClientUserID FROM Users").fetchall()}
        self.apply_identity_migration()
        self.assertTrue(before == self.snapshot_legacy(), "Migration changed legacy data")
        missing = self.query_one("""SELECT COUNT(*) FROM ClientUsers CU
            LEFT JOIN Users U ON U.LegacyClientUserID = CU.UserID WHERE U.UserID IS NULL""")[0]
        self.assertEqual(missing, 0)
        # Initial copy is byte-for-byte for credential and lockout fields.
        copies = self.connection.cursor().execute("""SELECT CU.UserID, CU.PasswordHash, CU.FailedAttempts,
            CU.IsLocked, CU.LastFailedAt, CU.CreatedAt, U.PasswordHash, U.FailedAttempts,
            U.IsLocked, U.LastFailedAt, U.CreatedAt
            FROM ClientUsers CU JOIN Users U ON U.LegacyClientUserID = CU.UserID""").fetchall()
        self.assertTrue(all(tuple(row[1:6]) == tuple(row[6:11]) for row in copies if row[0] not in mapped_ids),
                        "Newly imported credential/lockout fields differ")
        users_before = [tuple(row) for row in self.connection.cursor().execute("SELECT * FROM Users ORDER BY UserID").fetchall()]
        members_before = [tuple(row) for row in self.connection.cursor().execute("SELECT * FROM OrganizationMemberships ORDER BY UserID, OrganizationID").fetchall()]
        self.apply_identity_migration()
        self.assertTrue(users_before == [tuple(row) for row in self.connection.cursor().execute("SELECT * FROM Users ORDER BY UserID").fetchall()])
        self.assertTrue(members_before == [tuple(row) for row in self.connection.cursor().execute("SELECT * FROM OrganizationMemberships ORDER BY UserID, OrganizationID").fetchall()])

    def test_02_backfill_locked_legacy_account(self):
        cursor = self.connection.cursor()
        seller_id = int(cursor.execute("""INSERT Sellers (BusinessName, WhatsAppNumber, Email, DomainName)
            OUTPUT inserted.SellerID VALUES (?, ?, ?, ?)""",
            (self.identity["business"], self.identity["phone"], self.identity["email"], self.identity["domain"])).fetchone()[0])
        org_id = str(cursor.execute("INSERT Organizations (LegacySellerID,OrganizationName) OUTPUT inserted.OrganizationID VALUES (?,?)",
                                    (seller_id, self.identity["business"])).fetchone()[0])
        password_hash = dukaan.generate_password_hash(self.identity["password"])
        legacy_id = int(cursor.execute("""INSERT ClientUsers
            (SellerID,Username,PasswordHash,FailedAttempts,IsLocked,LastFailedAt)
            OUTPUT inserted.UserID VALUES (?,?,?,3,1,'2026-01-01')""",
            (seller_id, self.identity["username"], password_hash)).fetchone()[0])
        self.connection.commit()
        self.apply_identity_migration()
        row = self.query_one("SELECT UserID,PasswordHash,FailedAttempts,IsLocked,LastFailedAt FROM Users WHERE LegacyClientUserID=?", (legacy_id,))
        self.assertTrue(row.PasswordHash == password_hash)
        self.assertEqual(int(row.FailedAttempts), 3)
        self.assertTrue(row.IsLocked)
        self.assertEqual(row.LastFailedAt.year, 2026)
        self.assertEqual(self.query_one("SELECT Status FROM OrganizationMemberships WHERE UserID=? AND OrganizationID=?", (row.UserID, org_id))[0], "Active")
        _, response = self.login(self.identity)
        self.assertIn(b"Account locked", response.data)

    def test_00b_rbac_migration_founders_and_idempotence(self):
        sql = (Path(__file__).parents[1] / '8_OrganizationRoles.sql').read_text(encoding='utf-8')
        self.assertEqual(self.query_one('SELECT DB_NAME()')[0], 'DukaanDesk_Test')
        initial = self.query_one("SELECT COL_LENGTH('dbo.OrganizationMemberships','RoleName')")[0] is None
        if initial:
            # Exercise ambiguous founder backfill in a rollback-only transaction, including
            # the new DDL. No existing tables/data are dropped, reset, or overwritten.
            cursor = self.connection.cursor()
            sid = cursor.execute('INSERT Sellers (BusinessName,WhatsAppNumber,Email,DomainName) OUTPUT inserted.SellerID VALUES (?,?,?,?)',
                ('Ambiguous founder test', self.identity['phone'], self.identity['email'], self.identity['domain'])).fetchone()[0]
            oid = cursor.execute('INSERT Organizations (LegacySellerID,OrganizationName) OUTPUT inserted.OrganizationID VALUES (?,?)',
                (sid, 'Ambiguous founder test')).fetchone()[0]
            for index in range(2):
                name = f"historical-{self.identity['token']}-{index}"
                legacy = cursor.execute('INSERT ClientUsers (SellerID,Username,PasswordHash) OUTPUT inserted.UserID VALUES (?,?,?)',
                    (sid, name, 'synthetic-unusable')).fetchone()[0]
                uid = cursor.execute('INSERT Users (LegacyClientUserID,Email,Username,PasswordHash) OUTPUT inserted.UserID VALUES (?,?,?,?)',
                    (legacy, name+'@example.test', name, 'synthetic-unusable')).fetchone()[0]
                cursor.execute("INSERT OrganizationMemberships (UserID,OrganizationID,Status) VALUES (?,?,'Active')", (uid, oid))
            try:
                cursor.execute(sql)
                count = self.query_one('SELECT COUNT(*) FROM OrganizationMemberships WHERE OrganizationID=? AND RoleName IS NOT NULL', (oid,))[0]
                self.assertEqual(count, 0, 'Ambiguous historical employees must not become Owner')
            finally:
                self.connection.rollback()
        before = self.snapshot_legacy()
        self.connection.cursor().execute(sql)
        self.connection.commit()
        self.assertTrue(before == self.snapshot_legacy())
        if initial:
            wrong = self.query_one("""SELECT COUNT(*) FROM OrganizationMemberships M
                JOIN Users U ON U.UserID=M.UserID JOIN ClientUsers CU ON CU.UserID=U.LegacyClientUserID
                JOIN Organizations O ON O.OrganizationID=M.OrganizationID
                WHERE (M.RoleName='Owner' AND (O.LegacySellerID<>CU.SellerID OR
                    (SELECT COUNT(*) FROM ClientUsers C WHERE C.SellerID=O.LegacySellerID)<>1))
                   OR (M.RoleName IS NULL AND O.LegacySellerID=CU.SellerID AND
                    (SELECT COUNT(*) FROM ClientUsers C WHERE C.SellerID=O.LegacySellerID)=1)""")[0]
            self.assertEqual(wrong, 0)
        role_rows = {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM OrganizationMemberships').fetchall()}
        self.connection.cursor().execute(sql)
        self.connection.commit()
        self.assertTrue(role_rows == {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM OrganizationMemberships').fetchall()})

    def test_00c_rbac_policy_drift_fails_closed(self):
        sql = (Path(__file__).parents[1] / '8_OrganizationRoles.sql').read_text(encoding='utf-8')
        baseline = {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM RolePermissions').fetchall()}
        try:
            self.connection.cursor().execute("INSERT RolePermissions (RoleName,Permission) VALUES ('Support','members.roles')")
            with self.assertRaises(dukaan.pyodbc.Error) as raised:
                self.connection.cursor().execute(sql)
            self.assertIn('50032', str(raised.exception))
        finally:
            self.connection.rollback()
        self.assertTrue(baseline == {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM RolePermissions').fetchall()})

    def test_01_ambiguous_email_aborts_without_merging(self):
        before = self.snapshot_legacy()
        user_count = self.query_one("SELECT COUNT(*) FROM Users")[0]
        # Uncommitted duplicate legacy account; migration must roll back the entire transaction.
        self.connection.cursor().execute("""INSERT ClientUsers (SellerID, Username, PasswordHash)
            SELECT MIN(SellerID), ?, 'test-only-unusable-value' FROM Sellers""", ("ambiguous-" + self.identity["token"],))
        try:
            with self.assertRaises(dukaan.pyodbc.Error) as raised:
                self.apply_identity_migration()
            self.assertIn("50022", str(raised.exception))
        finally:
            self.connection.rollback()
        self.assertTrue(before == self.snapshot_legacy())
        self.assertEqual(user_count, self.query_one("SELECT COUNT(*) FROM Users")[0])

    def test_00d_invitation_migration_preserves_rows_and_is_idempotent(self):
        self.assertEqual(self.query_one('SELECT DB_NAME()')[0], 'DukaanDesk_Test')
        sql = (Path(__file__).parents[1] / '9_OrganizationInvitations.sql').read_text(encoding='utf-8')
        before = self.snapshot_legacy()
        users = {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM Users').fetchall()}
        members = {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM OrganizationMemberships').fetchall()}
        for _ in range(2):
            self.connection.cursor().execute(sql)
            self.connection.commit()
            self.assertTrue(before == self.snapshot_legacy())
            self.assertTrue(users == {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM Users').fetchall()})
            self.assertTrue(members == {tuple(row) for row in self.connection.cursor().execute('SELECT * FROM OrganizationMemberships').fetchall()})
        self.assertEqual(self.query_one("SELECT is_nullable FROM sys.columns WHERE object_id=OBJECT_ID('dbo.Users') AND name='LegacyClientUserID'")[0], 1)
        self.assertEqual(self.query_one("SELECT COUNT(*) FROM sys.foreign_keys WHERE parent_object_id=OBJECT_ID('dbo.OrganizationInvitations') AND is_disabled=0 AND is_not_trusted=0")[0],4)
        self.apply_identity_migration()  # Earlier migration stays compatible, no employee imports/merges.

    def invitation_post(self, client, path, **data):
        with client.session_transaction() as state:
            csrf = state.get('csrf_token')
        if not csrf:
            csrf = self.csrf(client, '/invitations/accept')
        return client.post(path, data={'csrf_token':csrf, **data})

    def invite(self, owner, email, role='Support'):
        with patch.dict(os.environ, {'APP_ENV':'development','DEV_INVITATION_LINKS':'true'}):
            response = self.invitation_post(owner, '/organization/invitations', email=email, role=role)
        self.assertEqual(response.status_code,201)
        match = re.search(rb'#token=([A-Za-z0-9_-]{43})',response.data)
        self.assertTrue(match is not None, 'Development invitation link missing')
        token = match[1].decode()
        row = self.query_one('SELECT InvitationID,TokenHash,Status FROM OrganizationInvitations WHERE TokenHash=?', (dukaan.invitation_digest(token),))
        self.assertTrue(row is not None)
        self.assertTrue(row.TokenHash != token)
        return token, str(row.InvitationID)

    def another_identity(self, suffix):
        return {**self.identity, 'username':self.identity['username']+suffix,
                'email':suffix+self.identity['email'], 'phone':self.identity['phone']+suffix,
                'domain':suffix+self.identity['domain']}

    def invitation_verification(self, client, token):
        with patch.object(dukaan,'send_invitation_email') as mail:
            self.assertEqual(self.invitation_post(client,'/invitations/accept',action='verify',token=token).status_code,200)
            return mail.call_args.args[2].splitlines()[1]

    def test_invitations_existing_accept_replay_email_and_tenant_guards(self):
        owner = self.signup(self.identity)
        recipient_identity = self.another_identity('2')
        recipient = self.signup(recipient_identity)
        token, iid = self.invite(owner, recipient_identity['email'], 'Operations')
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='accept',token=token).status_code,403)
        code = self.invitation_verification(recipient,token)
        # Logged-in inviter is not the invited identity; client tenant claims do not help.
        response = self.invitation_post(owner,'/invitations/accept',action='accept',token=token,verification=code,email=recipient_identity['email'])
        self.assertEqual(response.status_code,403)
        self.assertEqual(self.invitation_post(recipient,f'/organization/invitations/{iid}/revoke').status_code,404)
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='accept',token=token,verification=code).status_code,302)
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='accept',token=token).status_code,410)
        with owner.session_transaction() as state:
            org = state['user']['organization_id']
        with recipient.session_transaction() as state:
            uid = state['user']['global_user_id']
        self.assertEqual(self.query_one('SELECT RoleName FROM OrganizationMemberships WHERE UserID=? AND OrganizationID=?',(uid,org))[0],'Operations')
        self.assertEqual(self.invitation_post(recipient,'/organizations/switch',organization_id=org).status_code,302)
        self.assertEqual(recipient.get('/dashboard').status_code,200)
        self.assertEqual(self.invitation_post(recipient,'/organization/invitations',email='other@example.test',role='Admin').status_code,403)
        self.assertEqual(self.invitation_post(owner,'/organization/invitations',email=recipient_identity['email'],role='Admin').status_code,409)
        self.assertEqual(self.invitation_post(owner,f'/organization/members/{uid}/deactivate').status_code,302)
        self.assertEqual(recipient.get('/dashboard').status_code,302)
        self.assertEqual(self.invitation_post(owner,'/organization/invitations',email=recipient_identity['email'],role='Admin').status_code,409)

    def test_invitations_new_employee_requires_separate_mail_and_can_login(self):
        owner = self.signup(self.identity)
        for suffix in ('a','b'):  # SQL Server filtered uniqueness permits several NULL legacy links.
            email = suffix+self.identity['email']
            username = suffix+self.identity['username']
            token, iid = self.invite(owner,email,'Finance')
            employee = dukaan.app.test_client()
            data = dict(action='register',token=token,username=username,password=self.identity['password'],confirm_password=self.identity['password'])
            self.assertEqual(self.invitation_post(employee,'/invitations/accept',**data).status_code,403)
            with patch.object(dukaan,'send_invitation_email',side_effect=RuntimeError('not configured')):
                self.assertEqual(self.invitation_post(employee,'/invitations/accept',action='verify',token=token).status_code,503)
            with patch.object(dukaan,'send_invitation_email') as mail:
                self.assertEqual(self.invitation_post(employee,'/invitations/accept',action='verify',token=token).status_code,200)
                self.assertEqual(mail.call_args.args[0],email)
                code = mail.call_args.args[2].splitlines()[1]
            self.assertTrue(code != token)
            self.assertEqual(self.invitation_post(employee,'/invitations/accept',action='verify',token=token).status_code,429)
            self.assertEqual(self.invitation_post(employee,'/invitations/accept',**data,verification=token).status_code,403)
            self.assertEqual(self.invitation_post(employee,'/invitations/accept',**data,verification=code).status_code,302)
            self.assertEqual(self.invitation_post(employee,'/invitations/accept',**data,verification=code).status_code,410)
            row = self.query_one('SELECT LegacyClientUserID,PasswordHash FROM Users WHERE NormalizedEmail=?',(email,))
            self.assertIsNone(row.LegacyClientUserID)
            self.assertTrue(dukaan.check_password_hash(row.PasswordHash,self.identity['password']))
            self.assertIsNone(self.query_one('SELECT VerificationHash FROM OrganizationInvitations WHERE InvitationID=?',(iid,))[0])
            client, response = self.login({**self.identity,'email':email,'username':username})
            self.assertEqual(response.status_code,302)
            self.assertEqual(client.get('/dashboard').status_code,200)
            self.assertEqual(client.get('/summary').status_code,200)
            self.assertEqual(client.get('/organization/members').status_code,403)
            self.assertEqual(self.invitation_post(client,'/organization/invitations',email='bad@example.test',role='Owner').status_code,403)
            self.apply_identity_migration()

    def test_invitations_expiry_revocation_duplicate_pending_and_last_owner(self):
        owner = self.signup(self.identity)
        with owner.session_transaction() as state:
            uid = state['user']['global_user_id']
        self.assertEqual(self.invitation_post(owner,f'/organization/members/{uid}/deactivate').status_code,409)
        self.assertEqual(self.invitation_post(owner,'/organization/invitations',email='person@example.test',role='Owner').status_code,400)
        recipient = dukaan.app.test_client()
        for status in ('Expired','Revoked'):
            email = status.lower()+self.identity['email']
            token, iid = self.invite(owner,email)
            self.assertEqual(self.invitation_post(owner,'/organization/invitations',email=email,role='Support').status_code,409)
            if status == 'Revoked':
                self.assertEqual(self.invitation_post(owner,f'/organization/invitations/{iid}/revoke').status_code,302)
            else:
                self.connection.cursor().execute("UPDATE OrganizationInvitations SET CreatedAt=DATEADD(day,-3,SYSUTCDATETIME()),ExpiresAt=DATEADD(day,-1,SYSUTCDATETIME()) WHERE InvitationID=?",(iid,))
                self.connection.commit()
            self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='verify',token=token).status_code,410)
            self.assertEqual(self.query_one('SELECT Status FROM OrganizationInvitations WHERE InvitationID=?',(iid,))[0],status)
        page = owner.get('/organization/members')
        self.assertEqual(page.status_code,200)
        self.assertIn(b'Invite an employee',page.data)
        self.assertNotIn(token.encode(),page.data)

    def test_invitations_all_nonowners_denied_and_issuer_revocation(self):
        owner = self.signup(self.identity)
        admin = self.signup(self.another_identity('2'))
        with owner.session_transaction() as state:
            uid, org = state['user']['global_user_id'],state['user']['organization_id']
        with admin.session_transaction() as state:
            other_uid = state['user']['global_user_id']
        self.connection.cursor().execute("INSERT OrganizationMemberships (UserID,OrganizationID,Status,RoleName) VALUES (?,?,'Active','Owner')",(other_uid,org))
        self.connection.commit()
        token,iid = self.invite(owner,'new'+self.identity['email'])
        for role in ('Admin','Operations','Finance','Marketing','Support',None):
            self.connection.cursor().execute('UPDATE OrganizationMemberships SET RoleName=? WHERE UserID=? AND OrganizationID=?',(role,uid,org))
            self.connection.commit()
            for path, data in [('/organization/invitations',dict(email='next@example.test',role='Support')),
                (f'/organization/invitations/{iid}/revoke',{}),(f'/organization/members/{other_uid}/deactivate',{})]:
                with self.subTest(role=role,path=path):
                    self.assertEqual(self.invitation_post(owner,path,**data).status_code,403)
        recipient=dukaan.app.test_client()
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='verify',token=token).status_code,403)
        self.assertEqual(self.query_one('SELECT Status FROM OrganizationInvitations WHERE InvitationID=?',(iid,))[0],'Pending')

    def test_invitations_production_delivery_rollback_and_no_token_response(self):
        owner = self.signup(self.identity)
        email='new'+self.identity['email']
        with patch.dict(os.environ, {'APP_ENV':'production','DEV_INVITATION_LINKS':'true','APP_PUBLIC_URL':'https://app.example.test'}):
            with patch.object(dukaan,'send_invitation_email',side_effect=RuntimeError('mail unavailable')):
                response=self.invitation_post(owner,'/organization/invitations',email=email,role='Support')
                self.assertEqual(response.status_code,503)
                self.assertEqual(self.query_one('SELECT COUNT(*) FROM OrganizationInvitations WHERE Email=?',(email,))[0],0)
            with patch.object(dukaan,'send_invitation_email') as mail:
                response=self.invitation_post(owner,'/organization/invitations',email=email,role='Support')
                self.assertEqual(response.status_code,302)
                token=re.search(r'#token=([A-Za-z0-9_-]{43})',mail.call_args.args[2])[1]
                self.assertNotIn(token.encode(),response.data)
                self.assertEqual(mail.call_args.args[0],email)

    def test_invitations_concurrent_acceptance_and_duplicate_membership(self):
        owner = self.signup(self.identity)
        identity = self.another_identity('2')
        recipient = self.signup(identity)
        second, response = self.login(identity)
        self.assertEqual(response.status_code,302)
        token, iid = self.invite(owner,identity['email'])
        code = self.invitation_verification(recipient,token)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda client: self.invitation_post(client,'/invitations/accept',action='accept',token=token,verification=code).status_code,
                                        (recipient,second)))
        self.assertEqual(sorted(results),[302,410])
        with owner.session_transaction() as state:
            org = state['user']['organization_id']
        with recipient.session_transaction() as state:
            uid = state['user']['global_user_id']
        self.assertEqual(self.query_one('SELECT COUNT(*) FROM OrganizationMemberships WHERE UserID=? AND OrganizationID=?',(uid,org))[0],1)
        third_identity = self.another_identity('3')
        third = self.signup(third_identity)
        with third.session_transaction() as state:
            third_uid = state['user']['global_user_id']
        self.assertEqual(self.invitation_post(owner,f'/organization/members/{third_uid}/deactivate').status_code,404)
        token, iid = self.invite(owner,third_identity['email'],'Admin')
        self.connection.cursor().execute("INSERT OrganizationMemberships (UserID,OrganizationID,Status,RoleName) VALUES (?,?,'Inactive','Support')",(third_uid,org))
        self.connection.commit()
        self.assertEqual(self.invitation_post(third,'/invitations/accept',action='accept',token=token).status_code,409)
        self.assertEqual(tuple(self.query_one('SELECT Status,RoleName FROM OrganizationMemberships WHERE UserID=? AND OrganizationID=?',(third_uid,org))),('Inactive','Support'))

    def test_invitations_verification_expiry_and_employee_lockout(self):
        owner = self.signup(self.identity)
        email='new'+self.identity['email']
        username='new'+self.identity['username']
        token,iid = self.invite(owner,email)
        recipient=dukaan.app.test_client()
        with patch.object(dukaan,'send_invitation_email') as mail:
            self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='verify',token=token).status_code,200)
            code=mail.call_args.args[2].splitlines()[1]
        self.connection.cursor().execute("UPDATE OrganizationInvitations SET VerificationExpiresAt=DATEADD(second,-1,SYSUTCDATETIME()),VerificationSentAt=DATEADD(minute,-2,SYSUTCDATETIME()) WHERE InvitationID=?",(iid,))
        self.connection.commit()
        data=dict(action='register',token=token,username=username,password=self.identity['password'],confirm_password=self.identity['password'])
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',**data,verification=code).status_code,403)
        with patch.object(dukaan,'send_invitation_email') as mail:
            self.assertEqual(self.invitation_post(recipient,'/invitations/accept',action='verify',token=token).status_code,200)
            replacement=mail.call_args.args[2].splitlines()[1]
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',**data,verification=code).status_code,403)
        self.assertEqual(self.invitation_post(recipient,'/invitations/accept',**data,verification=replacement).status_code,302)
        identity={**self.identity,'email':email,'username':username}
        employee,response=self.login(identity)
        self.assertEqual(response.status_code,302)
        for _ in range(3):
            self.login(identity,password='incorrect-password')
        self.assertEqual(self.query_one('SELECT IsLocked FROM Users WHERE NormalizedEmail=?',(email,))[0],True)
        self.assertEqual(employee.get('/dashboard').status_code,302)

    def setUp(self):
        token = uuid.uuid4().hex[:12]
        phone_suffix = str(int(token, 16))[-12:]
        self.identity = {
            "token": token,
            "password": f"Safe-{token}-Password!",
            "email": f"owner-{token}@example.test",
            "username": f"owner-{token}",
            "business": f"Integration Shop {token}",
            "domain": f"shop-{token}.test",
            "phone": f"+92{phone_suffix}",
        }

    @staticmethod
    def csrf(client, path="/login"):
        client.get(path)
        with client.session_transaction() as current_session:
            return current_session["csrf_token"]

    def signup(self, identity):
        client = dukaan.app.test_client()
        response = client.post(
            "/signup",
            data={
                "csrf_token": self.csrf(client, "/signup"),
                "businessName": identity["business"],
                "whatsappNumber": identity["phone"],
                "email": identity["email"],
                "domainName": identity["domain"],
                "username": identity["username"],
                "password": identity["password"],
                "confirmPassword": identity["password"],
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))
        return client

    def login(self, identity, password=None):
        client = dukaan.app.test_client()
        response = client.post(
            "/login",
            data={
                "csrf_token": self.csrf(client),
                "email": identity["email"],
                "username": identity["username"],
                "password": password if password is not None else identity["password"],
            },
        )
        return client, response

    def place_order(self, identity, buyer_name, amount):
        client = dukaan.app.test_client()
        response = client.post(
            "/store-order",
            data={
                "csrf_token": self.csrf(client, f"/store/{identity['domain']}"),
                "domainName": identity["domain"],
                "buyerName": buyer_name,
                "phone": identity["phone"],
                "address": f"Integration address {identity['token']}",
                "totalAmount": amount,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"placed", response.data)

    def query_one(self, sql, params=()):
        return self.connection.cursor().execute(sql, params).fetchone()

    def test_real_sql_mvp_workflows(self):
        owner_client = self.signup(self.identity)

        user_row = self.query_one(
            """
            SELECT CU.PasswordHash,
                   CU.FailedAttempts,
                   CU.IsLocked,
                   S.SellerID,
                   Org.OrganizationID
            FROM ClientUsers CU
            INNER JOIN Sellers S ON S.SellerID = CU.SellerID
            INNER JOIN Organizations Org ON Org.LegacySellerID = S.SellerID
            WHERE CU.Username = ? AND S.Email = ?
            """,
            (self.identity["username"], self.identity["email"]),
        )
        self.assertIsNotNone(user_row)
        self.assertNotEqual(user_row.PasswordHash, self.identity["password"])
        self.assertTrue(dukaan.check_password_hash(user_row.PasswordHash, self.identity["password"]))
        seller_id = int(user_row.SellerID)
        organization_id = str(user_row.OrganizationID)
        with owner_client.session_transaction() as current_session:
            self.assertEqual(current_session["user"]["organization_id"], organization_id)

        owner_client, login_response = self.login(self.identity)
        self.assertEqual(login_response.status_code, 302)
        self.assertTrue(login_response.headers["Location"].endswith("/dashboard"))

        locked_identity = dict(self.identity)
        locked_identity.update(
            {
                "email": f"locked-{self.identity['token']}@example.test",
                "username": f"locked-{self.identity['token']}",
                "business": f"Locked Shop {self.identity['token']}",
                "domain": f"locked-{self.identity['token']}.test",
                "phone": f"+93{self.identity['phone'][3:]}",
            }
        )
        self.signup(locked_identity)
        locked_organization_id = str(
            self.query_one(
                """
                SELECT Org.OrganizationID
                FROM Organizations Org
                INNER JOIN Sellers S ON S.SellerID = Org.LegacySellerID
                WHERE S.DomainName = ?
                """,
                (locked_identity["domain"],),
            )[0]
        )
        self.assertNotEqual(locked_organization_id, organization_id)
        for _ in range(3):
            _, failed_response = self.login(locked_identity, "definitely-wrong")
            self.assertEqual(failed_response.status_code, 200)
        _, locked_response = self.login(locked_identity)
        self.assertEqual(locked_response.status_code, 200)
        self.assertIn(b"Account locked", locked_response.data)
        lock_row = self.query_one(
            "SELECT FailedAttempts, IsLocked FROM ClientUsers WHERE Username = ?",
            (locked_identity["username"],),
        )
        self.assertEqual(int(lock_row.FailedAttempts), 3)
        self.assertTrue(bool(lock_row.IsLocked))
        mirrored = self.query_one("""SELECT COUNT(*) FROM Users U JOIN ClientUsers CU ON CU.UserID=U.LegacyClientUserID
            WHERE U.Username=? AND U.FailedAttempts=CU.FailedAttempts AND U.IsLocked=CU.IsLocked
              AND U.LastFailedAt=CU.LastFailedAt""", (locked_identity["username"],))[0]
        self.assertEqual(mirrored, 1)

        legacy_identity = dict(self.identity)
        legacy_identity.update(
            {
                "email": f"legacy-{self.identity['token']}@example.test",
                "username": f"legacy-{self.identity['token']}",
                "business": f"Legacy Shop {self.identity['token']}",
                "domain": f"legacy-{self.identity['token']}.test",
                "phone": f"+95{self.identity['phone'][3:]}",
            }
        )
        self.signup(legacy_identity)
        self.connection.cursor().execute(
            "UPDATE ClientUsers SET PasswordHash = ? WHERE Username = ?",
            (legacy_identity["password"], legacy_identity["username"]),
        )
        self.connection.cursor().execute(
            "UPDATE Users SET PasswordHash = ? WHERE Username = ?",
            (legacy_identity["password"], legacy_identity["username"]),
        )
        self.connection.commit()
        _, legacy_login = self.login(legacy_identity)
        self.assertEqual(legacy_login.status_code, 302)
        upgraded_hash = self.query_one(
            "SELECT PasswordHash FROM ClientUsers WHERE Username = ?",
            (legacy_identity["username"],),
        )[0]
        self.assertNotEqual(upgraded_hash, legacy_identity["password"])
        self.assertTrue(dukaan.check_password_hash(upgraded_hash, legacy_identity["password"]))

        delivered_buyer = f"Delivered Buyer {self.identity['token']}"
        self.place_order(self.identity, delivered_buyer, "125.50")
        delivered_order = self.query_one(
            """
            SELECT O.OrderID, O.OrderStatus, O.DeliveryStatus
            FROM Orders O
            WHERE O.SellerID = ? AND O.BuyerName = ?
            """,
            (seller_id, delivered_buyer),
        )
        delivered_order_id = int(delivered_order.OrderID)
        self.assertEqual(delivered_order.OrderStatus, "Pending")
        self.assertIsNone(delivered_order.DeliveryStatus)
        initial_log_count = self.query_one(
            "SELECT COUNT(*) FROM MessageLogs WHERE OrderID = ?",
            (delivered_order_id,),
        )[0]
        self.assertEqual(initial_log_count, 1)

        action_response = owner_client.post(
            f"/orders/{delivered_order_id}/action",
            data={"csrf_token": self.csrf(owner_client), "action": "confirm", "search": ""},
        )
        self.assertEqual(action_response.status_code, 302)
        confirmed = self.query_one(
            "SELECT OrderStatus, DeliveryStatus FROM Orders WHERE OrderID = ?",
            (delivered_order_id,),
        )
        self.assertEqual((confirmed.OrderStatus, confirmed.DeliveryStatus), ("Confirmed", "Pending"))

        delivery_response = owner_client.post(
            f"/orders/{delivered_order_id}/status",
            data={"csrf_token": self.csrf(owner_client), "status": "delivered", "search": ""},
        )
        self.assertEqual(delivery_response.status_code, 302)
        delivered = self.query_one(
            "SELECT OrderStatus, DeliveryStatus FROM Orders WHERE OrderID = ?",
            (delivered_order_id,),
        )
        self.assertEqual((delivered.OrderStatus, delivered.DeliveryStatus), ("Confirmed", "Delivered"))
        delivered_log_count = self.query_one(
            "SELECT COUNT(*) FROM MessageLogs WHERE OrderID = ?",
            (delivered_order_id,),
        )[0]
        self.assertEqual(delivered_log_count, 3)
        delivered_messages = {
            row[0]
            for row in self.connection.cursor()
            .execute(
                "SELECT MessageContent FROM MessageLogs WHERE OrderID = ?",
                (delivered_order_id,),
            )
            .fetchall()
        }
        self.assertIn("System: Initial WhatsApp confirmation message queued.", delivered_messages)
        self.assertIn("Seller changed order status to Confirmed.", delivered_messages)
        self.assertIn("Seller changed delivery status to Delivered.", delivered_messages)

        cancelled_buyer = f"Cancelled Buyer {self.identity['token']}"
        self.place_order(self.identity, cancelled_buyer, "75.25")
        cancelled_order_id = int(
            self.query_one(
                "SELECT OrderID FROM Orders WHERE SellerID = ? AND BuyerName = ?",
                (seller_id, cancelled_buyer),
            )[0]
        )
        cancel_response = owner_client.post(
            f"/orders/{cancelled_order_id}/action",
            data={"csrf_token": self.csrf(owner_client), "action": "not_confirm", "search": ""},
        )
        self.assertEqual(cancel_response.status_code, 302)
        cancelled = self.query_one(
            "SELECT OrderStatus, DeliveryStatus FROM Orders WHERE OrderID = ?",
            (cancelled_order_id,),
        )
        self.assertEqual(cancelled.OrderStatus, "Cancelled")
        self.assertIsNone(cancelled.DeliveryStatus)
        cancelled_log_count = self.query_one(
            "SELECT COUNT(*) FROM MessageLogs WHERE OrderID = ?",
            (cancelled_order_id,),
        )[0]
        self.assertEqual(cancelled_log_count, 2)
        cancelled_messages = {
            row[0]
            for row in self.connection.cursor()
            .execute(
                "SELECT MessageContent FROM MessageLogs WHERE OrderID = ?",
                (cancelled_order_id,),
            )
            .fetchall()
        }
        self.assertIn("Seller changed order status to Cancelled.", cancelled_messages)

        isolated_buyer = f"Isolated Buyer {self.identity['token']}"
        self.place_order(locked_identity, isolated_buyer, "99.00")
        isolated_order = self.query_one(
            """
            SELECT O.OrderID, O.OrderStatus, S.SellerID
            FROM Orders O
            INNER JOIN Sellers S ON S.SellerID = O.SellerID
            WHERE S.DomainName = ? AND O.BuyerName = ?
            """,
            (locked_identity["domain"], isolated_buyer),
        )
        isolation_response = owner_client.post(
            f"/orders/{int(isolated_order.OrderID)}/action",
            data={"csrf_token": self.csrf(owner_client), "action": "confirm", "search": ""},
        )
        self.assertEqual(isolation_response.status_code, 302)
        isolated_status = self.query_one(
            "SELECT OrderStatus FROM Orders WHERE OrderID = ?",
            (int(isolated_order.OrderID),),
        )[0]
        self.assertEqual(isolated_status, "Pending")

        organization_guard_buyer = f"Organization Guard Buyer {self.identity['token']}"
        self.place_order(self.identity, organization_guard_buyer, "33.00")
        organization_guard_order_id = int(
            self.query_one(
                "SELECT OrderID FROM Orders WHERE SellerID = ? AND BuyerName = ?",
                (seller_id, organization_guard_buyer),
            )[0]
        )
        with owner_client.session_transaction() as current_session:
            session_user = dict(current_session["user"])
            session_user["organization_id"] = locked_organization_id
            current_session["user"] = session_user
        mismatched_dashboard = owner_client.get("/dashboard")
        self.assertEqual(mismatched_dashboard.status_code, 302)
        self.assertTrue(mismatched_dashboard.location.endswith("/login"))
        self.assertNotIn(organization_guard_buyer.encode(), mismatched_dashboard.data)
        mismatched_update = owner_client.post(
            f"/orders/{organization_guard_order_id}/action",
            data={
                "csrf_token": self.csrf(owner_client),
                "action": "confirm",
                "organization_id": organization_id,
                "search": "",
            },
        )
        self.assertEqual(mismatched_update.status_code, 302)
        guarded_status = self.query_one(
            "SELECT OrderStatus FROM Orders WHERE OrderID = ?",
            (organization_guard_order_id,),
        )[0]
        self.assertEqual(guarded_status, "Pending")
        owner_client, login_response = self.login(self.identity)
        self.assertEqual(login_response.status_code, 302)

        dashboard_response = owner_client.get("/dashboard")
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertNotIn(isolated_buyer.encode(), dashboard_response.data)
        summary_response = owner_client.get("/summary")
        self.assertEqual(summary_response.status_code, 200)
        self.assertIn(b"Rs. 125.50", summary_response.data)
        self.assertIn(delivered_buyer.encode(), summary_response.data)
        self.assertIn(cancelled_buyer.encode(), summary_response.data)

        constraint_row = self.query_one(
            """
            SELECT COUNT(*)
            FROM sys.foreign_keys
            WHERE name = 'FK_Orders_SellerBuyer' AND is_disabled = 0 AND is_not_trusted = 0
            """
        )
        self.assertEqual(constraint_row[0], 1)

    def test_membership_switching_and_revocation(self):
        client = self.signup(self.identity)
        second = dict(self.identity, email=f"second-{self.identity['token']}@example.test",
                      username=f"second-{self.identity['token']}", domain=f"second-{self.identity['token']}.test",
                      phone=f"+96{self.identity['phone'][3:]}", business="Second Membership Test Shop")
        self.signup(second)
        with client.session_transaction() as current_session:
            original_user = dict(current_session["user"])
        global_id = original_user["global_user_id"]
        target = self.query_one("""SELECT O.OrganizationID, S.SellerID FROM Organizations O
            JOIN Sellers S ON S.SellerID=O.LegacySellerID WHERE S.DomainName=?""", (second["domain"],))
        target_org, target_seller = str(target[0]), int(target[1])
        self.place_order(second, "Membership Buyer " + self.identity["token"], "45.00")
        order_id = int(self.query_one("SELECT MAX(OrderID) FROM Orders WHERE SellerID=?", (target_seller,))[0])
        token = self.csrf(client)
        self.assertEqual(client.post("/organizations/switch", data={"csrf_token": token, "organization_id": target_org}).status_code, 403)
        # Only test fixture SQL provisions membership; there is no membership-creation route.
        self.connection.cursor().execute("INSERT OrganizationMemberships (UserID, OrganizationID) VALUES (?, ?)", (global_id, target_org))
        self.connection.commit()
        self.assertEqual(client.post("/organizations/switch", data={"csrf_token": token, "organization_id": target_org}).status_code, 403)
        self.connection.cursor().execute("UPDATE OrganizationMemberships SET Status='Active', RoleName='Operations' WHERE UserID=? AND OrganizationID=?", (global_id, target_org))
        self.connection.commit()
        self.assertIn(b"organization-select", client.get("/dashboard").data)
        self.assertEqual(client.post("/organizations/switch", data={"csrf_token": token, "organization_id": target_org, "seller_id": 9999}).status_code, 302)
        with client.session_transaction() as current_session:
            switched = dict(current_session["user"])
            self.assertEqual(switched["seller_id"], target_seller)
            self.assertEqual(switched["global_user_id"], global_id)
            self.assertNotEqual(current_session["csrf_token"], token)
        self.assertIn(("Membership Buyer " + self.identity["token"]).encode(), client.get("/dashboard").data)
        token = self.csrf(client)
        client.post(f"/orders/{order_id}/action", data={"csrf_token": token, "action": "confirm"})
        self.assertEqual(self.query_one("SELECT OrderStatus FROM Orders WHERE OrderID=?", (order_id,))[0], "Confirmed")
        self.connection.cursor().execute("UPDATE OrganizationMemberships SET Status='Revoked' WHERE UserID=? AND OrganizationID=?", (global_id, target_org))
        self.connection.commit()
        self.apply_identity_migration()
        self.assertEqual(self.query_one("SELECT Status FROM OrganizationMemberships WHERE UserID=? AND OrganizationID=?", (global_id, target_org))[0], "Revoked")
        denied = client.post(f"/orders/{order_id}/status", data={"csrf_token": token, "status": "delivered"})
        self.assertTrue(denied.location.endswith("/login"))
        self.assertEqual(self.query_one("SELECT DeliveryStatus FROM Orders WHERE OrderID=?", (order_id,))[0], "Pending")
        rows, source = dukaan.fetch_orders_for_dashboard(target_seller, target_org, global_user_id=global_id)
        self.assertEqual((rows, source), ([], "database"))
        # Inactive global identities invalidate otherwise valid signed sessions and login.
        client, response = self.login(self.identity)
        self.assertEqual(response.status_code, 302)
        # A legacy signed session upgrades to a global identity via its actual membership.
        with client.session_transaction() as current_session:
            old_user = dict(current_session["user"])
            old_user.pop("global_user_id")
            current_session["user"] = old_user
        self.assertEqual(client.get("/dashboard").status_code, 200)
        with client.session_transaction() as current_session:
            self.assertEqual(current_session["user"]["global_user_id"], global_id)
        self.connection.cursor().execute("UPDATE Users SET IsActive=0 WHERE UserID=?", (global_id,))
        self.connection.commit()
        self.assertTrue(client.get("/dashboard").location.endswith("/login"))
        _, denied_login = self.login(self.identity)
        self.assertEqual(denied_login.status_code, 200)

    def test_rbac_all_roles_management_and_immediate_changes(self):
        owner = self.signup(self.identity)
        employee = dict(self.identity, email=f"staff-{self.identity['token']}@example.test",
                        username=f"staff-{self.identity['token']}", domain=f"staff-{self.identity['token']}.test",
                        phone=f"+97{self.identity['phone'][3:]}", business='RBAC staff home')
        member = self.signup(employee)
        with owner.session_transaction() as current:
            owner_user = dict(current['user'])
        with member.session_transaction() as current:
            member_user = dict(current['user'])
        oid, sid = owner_user['organization_id'], owner_user['seller_id']
        uid = member_user['global_user_id']
        self.connection.cursor().execute("INSERT OrganizationMemberships (UserID,OrganizationID,Status,RoleName) VALUES (?,?,'Active','Support')", (uid, oid))
        self.connection.commit()
        response = member.post('/organizations/switch', data={'csrf_token':self.csrf(member), 'organization_id':oid})
        self.assertEqual(response.status_code, 302)
        policies = {
            'Owner': (True, True, True), 'Admin': (True, True, True),
            'Operations': (False, True, False), 'Finance': (True, False, False),
            'Marketing': (True, False, False), 'Support': (False, False, False),
        }
        for role, (summary, writes, roster) in policies.items():
            with self.subTest(role=role):
                self.connection.cursor().execute('UPDATE OrganizationMemberships SET RoleName=? WHERE UserID=? AND OrganizationID=?', (role, uid, oid))
                self.connection.commit()
                order_ids = []
                for kind in ('confirm','cancel','delivery'):
                    buyer = f"RBAC {role} {kind} {self.identity['token']}"
                    self.place_order(self.identity, buyer, '12.00')
                    order_ids.append(int(self.query_one('SELECT OrderID FROM Orders WHERE SellerID=? AND BuyerName=?', (sid,buyer))[0]))
                owner.post(f'/orders/{order_ids[2]}/action', data={'csrf_token':self.csrf(owner), 'action':'confirm'})
                page = member.get('/dashboard')
                self.assertEqual(page.status_code, 200)
                self.assertEqual(b'href="/summary"' in page.data, summary)
                self.assertEqual(b'href="/organization/members"' in page.data, roster)
                self.assertEqual(f'action="/orders/{order_ids[0]}/action"'.encode() in page.data, writes)
                self.assertEqual(member.get('/summary').status_code, 200 if summary else 403)
                self.assertEqual(member.get('/organization/members').status_code, 200 if roster else 403)
                for order_id, route, field, value in (
                    (order_ids[0],'action','action','confirm'),
                    (order_ids[1],'action','action','not_confirm'),
                    (order_ids[2],'status','status','delivered'),
                ):
                    response = member.post(f'/orders/{order_id}/{route}', data={
                        'csrf_token':self.csrf(member), field:value, 'role':'Owner', 'organization_id':member_user['organization_id']})
                    self.assertEqual(response.status_code, 302 if writes else 403)
                actual = [self.query_one('SELECT OrderStatus,DeliveryStatus FROM Orders WHERE OrderID=?',(order_id,)) for order_id in order_ids]
                self.assertEqual(actual[0].OrderStatus, 'Confirmed' if writes else 'Pending')
                self.assertEqual(actual[1].OrderStatus, 'Cancelled' if writes else 'Pending')
                self.assertEqual(actual[2].DeliveryStatus, 'Delivered' if writes else 'Pending')
                denied_role = member.post(f'/organization/members/{uid}/role', data={
                    'csrf_token':self.csrf(member), 'role':role})
                self.assertEqual(denied_role.status_code, 302 if role=='Owner' else 403)
                # Switching is available to every defined role, with target membership validation.
                self.assertEqual(member.post('/organizations/switch', data={'csrf_token':self.csrf(member),
                    'organization_id':member_user['organization_id']}).status_code, 302)
                self.assertEqual(member.post('/organizations/switch', data={'csrf_token':self.csrf(member),
                    'organization_id':oid}).status_code, 302)
        # Roleless memberships deny even previously authenticated cookies.
        self.connection.cursor().execute('UPDATE OrganizationMemberships SET RoleName=NULL WHERE UserID=? AND OrganizationID=?', (uid,oid))
        self.connection.commit()
        self.assertEqual(member.get('/dashboard').status_code, 403)
        self.assertEqual(member.post('/organizations/switch', data={'csrf_token':self.csrf(member),
            'organization_id':member_user['organization_id']}).status_code, 403)
        # Owner can assign a role without creating/reactivating a membership.
        self.assertEqual(owner.post(f'/organization/members/{uid}/role', data={
            'csrf_token':self.csrf(owner), 'role':'Admin'}).status_code, 302)
        self.assertEqual(member.get('/organization/members').status_code, 200)
        self.assertEqual(member.post(f'/organization/members/{uid}/role', data={
            'csrf_token':self.csrf(member), 'role':'Owner'}).status_code, 403)
        foreign_id = int(self.query_one('SELECT MIN(UserID) FROM Users')[0])
        self.assertEqual(owner.post(f'/organization/members/{foreign_id}/role', data={
            'csrf_token':self.csrf(owner), 'role':'Owner', 'organization_id':member_user['organization_id']}).status_code, 404)
        self.assertEqual(owner.post(f'/organization/members/{uid}/role', data={
            'csrf_token':self.csrf(owner), 'role':'invented'}).status_code, 400)
        self.assertEqual(owner.post(f"/organization/members/{owner_user['global_user_id']}/role", data={
            'csrf_token':self.csrf(owner), 'role':'Support'}).status_code, 409)
        # Cross-tenant orders remain inaccessible even for Admin.
        self.place_order(employee, 'Private staff order '+self.identity['token'], '50.00')
        foreign_order = self.query_one('SELECT MAX(OrderID) FROM Orders WHERE SellerID=?', (member_user['seller_id'],))[0]
        self.assertNotIn(('Private staff order '+self.identity['token']).encode(), member.get('/dashboard').data)
        member.post(f'/orders/{foreign_order}/action', data={'csrf_token':self.csrf(member),'action':'confirm'})
        self.assertEqual(self.query_one('SELECT OrderStatus FROM Orders WHERE OrderID=?',(foreign_order,))[0], 'Pending')
        self.assertEqual(self.query_one('SELECT COUNT(*) FROM MessageLogs WHERE OrderID=?',(foreign_order,))[0], 1)

    def test_organization_backfill_constraints_and_immutable_mapping(self):
        mapping_counts = self.query_one(
            """
            SELECT
                (SELECT COUNT(*) FROM Sellers) AS SellerCount,
                (SELECT COUNT(*) FROM Organizations) AS OrganizationCount,
                (
                    SELECT COUNT(*)
                    FROM Sellers S
                    LEFT JOIN Organizations Org ON Org.LegacySellerID = S.SellerID
                    WHERE Org.OrganizationID IS NULL
                ) AS MissingMappings,
                (
                    SELECT COUNT(*)
                    FROM (
                        SELECT LegacySellerID
                        FROM Organizations
                        GROUP BY LegacySellerID
                        HAVING COUNT(*) <> 1
                    ) Duplicates
                ) AS DuplicateMappings
            """
        )
        self.assertEqual(int(mapping_counts.SellerCount), int(mapping_counts.OrganizationCount))
        self.assertEqual(int(mapping_counts.MissingMappings), 0)
        self.assertEqual(int(mapping_counts.DuplicateMappings), 0)

        schema_state = self.query_one(
            """
            SELECT
                (SELECT COUNT(*) FROM sys.key_constraints
                 WHERE name = 'PK_Organizations') AS PrimaryKeyCount,
                (SELECT COUNT(*) FROM sys.key_constraints
                 WHERE name = 'UQ_Organizations_LegacySellerID') AS UniqueMappingCount,
                (SELECT COUNT(*) FROM sys.foreign_keys
                 WHERE name = 'FK_Organizations_Sellers'
                   AND is_disabled = 0 AND is_not_trusted = 0) AS TrustedForeignKeyCount,
                (SELECT COUNT(*) FROM sys.triggers
                 WHERE name = 'trg_Organizations_ImmutableIdentity'
                   AND is_disabled = 0) AS EnabledTriggerCount
            """
        )
        self.assertEqual(tuple(int(value) for value in schema_state), (1, 1, 1, 1))

        seller_id = int(self.query_one("SELECT MIN(SellerID) FROM Sellers")[0])
        cursor = self.connection.cursor()
        with self.assertRaises(dukaan.pyodbc.Error):
            cursor.execute(
                """
                UPDATE Organizations
                SET LegacySellerID = LegacySellerID
                WHERE LegacySellerID = ?
                """,
                (seller_id,),
            )
        self.connection.rollback()
        self.assertEqual(
            int(
                self.query_one(
                    "SELECT COUNT(*) FROM Organizations WHERE LegacySellerID = ?",
                    (seller_id,),
                )[0]
            ),
            1,
        )

    def test_concurrent_seller_number_allocation(self):
        self.signup(self.identity)
        seller_id = int(
            self.query_one(
                "SELECT SellerID FROM Sellers WHERE DomainName = ?",
                (self.identity["domain"],),
            )[0]
        )

        payloads = [
            {
                "domain_name": self.identity["domain"],
                "buyer_name": f"Concurrent Buyer {self.identity['token']} {index}",
                "phone": f"+94{self.identity['phone'][3:]}{index}",
                "address": f"Concurrent address {index}",
                "total_amount": "10.00",
            }
            for index in range(4)
        ]
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(dukaan.place_public_order, payloads))

        order_numbers = sorted(result["seller_order_no"] for result in results)
        buyer_numbers = sorted(result["seller_buyer_no"] for result in results)
        self.assertEqual(order_numbers, [1, 2, 3, 4])
        self.assertEqual(buyer_numbers, [1, 2, 3, 4])

        counts = self.query_one(
            """
            SELECT COUNT(*) AS Orders,
                   COUNT(DISTINCT SellerOrderNo) AS DistinctOrderNumbers,
                   COUNT(DISTINCT BuyerID) AS DistinctBuyers
            FROM Orders
            WHERE SellerID = ?
            """,
            (seller_id,),
        )
        self.assertEqual(tuple(counts), (4, 4, 4))
        log_count = self.query_one(
            """
            SELECT COUNT(*)
            FROM MessageLogs L
            INNER JOIN Orders O ON O.OrderID = L.OrderID
            WHERE O.SellerID = ?
            """,
            (seller_id,),
        )[0]
        self.assertEqual(log_count, 4)


if __name__ == "__main__":
    unittest.main()
