# DukaanDesk

DukaanDesk is a server-rendered Flask and Microsoft SQL Server MVP for cash-on-delivery order operations. A seller can onboard one business/organization, expose a domain-scoped order form, review incoming orders, confirm or cancel them, record delivery outcomes, and view twelve-month summaries.

The current code supports global users, organization memberships, organization-scoped roles, and Owner-managed employee invitations while retaining one store/domain per seller. Shopify/WooCommerce/custom-store connectors, platform administration, and subscriptions remain future work.

## Current features

- Seller signup and session-based login.
- Global user identities and active organization memberships, with a small organization selector for users who have access to multiple organizations.
- SQL-backed Owner, Admin, Operations, Finance, Marketing, and Support roles. Owner can assign roles, invite employees to non-Owner roles, revoke pending invitations, and deactivate memberships with last-Owner protection.
- Single-use hashed invitation tokens and separate emailed verification codes; link possession alone never activates membership. SMTP is required for acceptance, including existing users.
- Werkzeug `scrypt` password hashes for new users; a successful legacy plaintext login upgrades that row in place.
- Lockout after three failed database or demo login attempts.
- Explicit, opt-in, in-memory demo mode; it is off by default and never silently exposes demo data to database users.
- Public order entry at `/store/<seller-domain>`.
- Immutable organization tenant IDs with a one-to-one mapping to legacy sellers.
- Organization- and seller-scoped dashboard queries and mutations. Switching accepts an organization selection but authorizes it against active memberships in SQL; protected requests revalidate access every time.
- Seller-scoped buyers and order numbers, preserving the existing database model.
- Pending order confirmation/cancellation and one-way delivery outcomes.
- Delivered-revenue KPIs, search, and twelve-month delivered/cancelled/returned summaries.
- CSRF tokens on every state-changing form, hardened session cookies, security headers, request-size limits, and debug mode off by default.
- SQL Server view, set-based order-log trigger, message audit rows, and non-destructive migration checks.
- Automated unit and Flask route tests that do not require SQL Server.

## Repository map

```text
app.py                 Flask configuration, routes, security, DB access, demo mode
public/                Jinja HTML templates and shared CSS
tests/test_app.py      Automated unit and route tests
1_Schema.sql           Fresh database installer; aborts if CODManager exists
2_Logic.sql            Pending-confirmations view and order insert trigger
3_DataTesting.sql      Optional idempotent development seed data
4_Reports.sql          Read-only reporting queries
5_Migration.sql        Transactional hardening migration for an existing database
6_Organizations.sql    Additive organization tenant migration and safe seller backfill
7_UsersMemberships.sql Global identities, membership constraints, and legacy backfill
8_OrganizationRoles.sql Membership role assignments, explicit grants, safe founder backfill
9_OrganizationInvitations.sql Invitations and optional immutable legacy identity links
tests/test_invitations.py Offline invitation security/transport tests
tests/test_sql_integration.py Guarded SQL migration and workflow tests
public/_organization_selector.html  Shared selector for multiple active memberships
public/members.html    Roster, Owner-only roles, invitations, and deactivation
public/invitation_accept.html Recipient verification and acceptance/registration
public/invitation_created.html Local-development-only one-time invitation link
checking.sql           User-owned ad-hoc query (not part of setup)
reset.sql              Manual development unlock helper; review before use
requirements.txt       Python runtime dependencies
package.json           Legacy Node manifest; npm scripts delegate to Python
PROJECT_CONTEXT.md     Detailed implementation handoff
ROADMAP.md             Completed work and prioritized future direction
```

## Prerequisites

- Python 3.10 or newer.
- Microsoft SQL Server or Azure SQL reachable from the application environment.
- Microsoft ODBC Driver 18 for SQL Server.
- A SQL client such as `sqlcmd`, SSMS, or Azure Data Studio for manual schema setup.

The development server is sufficient for local/Codespace evaluation only. A production WSGI server, managed secrets, TLS, monitoring, backup/restore validation, and external security testing are still required before launch.

## Install

### PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Linux / GitHub Codespaces

Install Microsoft ODBC Driver 18 using Microsoft's instructions for the Codespace's Linux distribution, then run:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Database setup

For a brand-new local database, run these manually in order:

1. `1_Schema.sql`
2. `2_Logic.sql`
3. `3_DataTesting.sql` (optional development data)
4. `7_UsersMemberships.sql` in the explicitly selected application database
5. `8_OrganizationRoles.sql` in the same application database
6. `9_OrganizationInvitations.sql` in the same application database

`1_Schema.sql` refuses to continue if `CODManager` already exists. It no longer drops a database. The fresh schema includes `Organizations`; `2_Logic.sql` installs both the order-log trigger and organization-identity protection.

For an existing pre-Phase-2.1 database, review and run migrations 5, 6, 7, 8, then 9. A Phase 2.1 database needs 7–9; a Phase 2.2 database needs 8–9; Phase 2.3 needs 9. Stop application writes during migration and update all processes together. Back up non-disposable deployments before any separately authorized migration.

Migration 7 has no `USE` statement; select the database explicitly. It copies each legacy account into its own global user with the exact password hash, failure count, lock flag, failure timestamp, and creation timestamp. Email uniqueness uses trimmed/lowercase email. Ambiguous duplicate emails (including several legacy accounts under one seller email) abort the transaction for manual ownership resolution; there is no automatic identity merge. Reruns import only unmapped accounts and never overwrite newer authentication state or restore revoked memberships.

No database script is run automatically by Flask. `Users` is now the authentication authority; the app mirrors authentication changes to `ClientUsers` in the same transaction. Legacy-only SQL helpers such as `reset.sql` must not be used to administer current credentials or unlock accounts.

The optional seed credentials are:

```text
Email:    waqtoro@example.com
Username: waqtoro-admin
Password: ChangeMe123!
```

Change or remove seeded credentials outside local development.

## Configuration

Set environment variables in the shell or deployment secret manager. Do not commit a `.env` file.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | random per process | Required stable secret for persistent/multi-worker sessions |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `DB_SERVER` | `.\SQLEXPRESS` | SQL Server host/instance |
| `DB_PORT` | unset | Optional SQL Server port |
| `DB_NAME` | `CODManager` | Database name |
| `DB_DRIVER` | `ODBC Driver 18 for SQL Server` | Installed ODBC driver name |
| `DB_USERNAME` / `DB_PASSWORD` | unset | SQL authentication; if absent, trusted authentication is used |
| `DB_ENCRYPT` | `true` | ODBC transport encryption |
| `DB_TRUST_SERVER_CERTIFICATE` | `false` | Use `true` only for a controlled local/self-signed server |
| `DB_CONNECTION_TIMEOUT` | `5` | Connection timeout in seconds |
| `APP_HOST` | `0.0.0.0` | Development server bind address |
| `PORT` | `3000` | HTTP port |
| `FLASK_DEBUG` | `false` | Local debugging only |

Example for a Codespace connecting to a SQL-authenticated development server:

```bash
export SESSION_SECRET='replace-with-a-long-random-value'
export DB_SERVER='your-sql-host'
export DB_PORT='1433'
export DB_NAME='CODManager'
export DB_USERNAME='your-app-user'
export DB_PASSWORD='set-this-in-codespace-secrets'
export DB_ENCRYPT='true'
export DB_TRUST_SERVER_CERTIFICATE='false'
python app.py
```

Open the forwarded port 3000. Seller workflow: `/signup` → `/dashboard`; buyer workflow: `/store/<domain-name>`.

### Explicit demo mode

Demo mode is off by default. It uses isolated process memory and loses changes on restart. It is intended only for UI evaluation when SQL Server is unavailable.

```powershell
$env:SESSION_SECRET = "replace-with-a-long-random-value"
$env:DEMO_MODE = "true"
$env:DEMO_EMAIL = "demo@example.com"
$env:DEMO_USERNAME = "demo-owner"
$env:DEMO_PASSWORD = "choose-a-demo-password"
$env:DEMO_DOMAIN = "demo.local"
python app.py
```

If database login raises an availability/schema error and the submitted credentials match the configured demo account, the app starts an isolated demo session. Database users never receive demo orders. Orders submitted to the configured demo domain are also kept only in memory.

## Test

No database service is required for the automated suite:

```powershell
python -m unittest discover -s tests -v
```

or:

```powershell
python -m pytest -q -p no:cacheprovider
```

Syntax and dependency checks:

```powershell
python -m py_compile app.py tests/test_app.py tests/test_sql_integration.py
python -m pip check
```

### Disposable SQL Server integration test

The integration suite has a hard safety gate: it skips unless `RUN_SQL_INTEGRATION_TESTS=1` and `DB_NAME` is exactly `DukaanDesk_Test`; it also verifies `DB_NAME()` before writing. It applies/reruns migrations 7–9, creates uniquely named synthetic rows, and verifies full pre-existing row values in memory without printing credentials. Duplicate-email rollback fixtures can leave identity-number gaps. No cleanup deletes run. Some membership states use trusted fixture SQL; invitation creation/acceptance/revocation/deactivation are also exercised through Flask. SMTP delivery is mocked, not sent externally.

PowerShell configuration for the verified local instance:

```powershell
$env:DB_SERVER = "localhost\MSSQLSERVER01"
$env:DB_NAME = "DukaanDesk_Test"
$env:DB_ENCRYPT = "true"
$env:DB_TRUST_SERVER_CERTIFICATE = "true"
$env:SESSION_SECRET = "integration-test-only"
$env:RUN_SQL_INTEGRATION_TESTS = "1"

python -m pytest tests/test_sql_integration.py -q -p no:cacheprovider -vv
python -m pytest -q -p no:cacheprovider
```

For a first-time setup only, first confirm that the target is absent with a read-only query. The existing schema aborts if the substituted target already exists:

```powershell
sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -d master -Q "SELECT name FROM sys.databases WHERE name = N'DukaanDesk_Test';"

$schemaText = (Get-Content -LiteralPath "1_Schema.sql" -Raw).Replace("CODManager", "DukaanDesk_Test")
$schemaText | sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -b -d master

$logicText = (Get-Content -LiteralPath "2_Logic.sql" -Raw).Replace("CODManager", "DukaanDesk_Test")
$logicText | sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -b -d master
```

Do not run those setup commands when `DukaanDesk_Test` already exists. Never substitute an existing or production database name. `3_DataTesting.sql` and `reset.sql` are not needed for integration verification.

For the already-created disposable test database, inspect it first and then adapt only the organization migration in memory:

```powershell
sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -d DukaanDesk_Test -Q "SELECT DB_NAME(), COUNT(*) FROM dbo.Sellers GROUP BY DB_NAME();"

$migrationText = (Get-Content -LiteralPath "6_Organizations.sql" -Raw).Replace("USE CODManager;", "USE DukaanDesk_Test;")
$migrationText | sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -b
```

Do not use this substitution for any database whose disposable ownership is uncertain.

### Phase 2.2 migration and local runtime

For the confirmed disposable Phase 2.1 database, run a read-only preflight before migration. The duplicate-email and missing-mapping counts must be zero; stop for manual review otherwise:

```powershell
sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -d DukaanDesk_Test -b -Q "SELECT DB_NAME() AS TargetDatabase; SELECT COUNT(*) AS AmbiguousEmailGroups FROM (SELECT LOWER(LTRIM(RTRIM(S.Email))) AS EmailKey FROM ClientUsers CU JOIN Sellers S ON S.SellerID=CU.SellerID GROUP BY LOWER(LTRIM(RTRIM(S.Email))) HAVING COUNT(*)>1) D; SELECT COUNT(*) AS MissingMappings FROM ClientUsers CU LEFT JOIN Organizations O ON O.LegacySellerID=CU.SellerID WHERE O.OrganizationID IS NULL;"
sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -d DukaanDesk_Test -b -i 7_UsersMemberships.sql
```

The current `DukaanDesk_Test` is already migrated. Run the app with Windows authentication:

```powershell
$env:DB_SERVER = "localhost\MSSQLSERVER01"
$env:DB_NAME = "DukaanDesk_Test"
$env:DB_ENCRYPT = "true"
$env:DB_TRUST_SERVER_CERTIFICATE = "true"
$env:SESSION_SECRET = "replace-with-a-long-random-local-secret"
python -B app.py
```

Login keeps the existing email/username/password form. The default organization is the legacy seller organization if active, otherwise another active membership. The selector offers assigned active memberships and verifies the target permission in SQL. Revoked/inactive accounts or sessions whose selected membership is no longer active must sign in again. "Active" means a verified database membership, not verified email ownership. Unassigned roles deny all protected operations pending manual review.

### Phase 2.3 permissions

Assignments belong to each membership, not to the user globally. The six built-in role definitions are shared policy. Every protected request reads the current role and explicit grants from SQL; signed-cookie role/permission claims are not authority. Order and roster queries repeat the permission and tenant checks. Missing roles/grants deny access. UI controls follow the same permissions.

| Role | Dashboard | Summary | Confirm/cancel | Delivery | Switch organization | View members | Assign roles |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Owner | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Admin | Yes | Yes | Yes | Yes | Yes | Yes | No |
| Operations | Yes | No | Yes | Yes | Yes | No | No |
| Finance | Yes | Yes | No | No | Yes | No | No |
| Marketing | Yes | Yes | No | No | Yes | No | No |
| Support | Yes | No | No | No | Yes | No | No |

Dashboard permission includes the current buyer contact details, amounts, and revenue KPIs; field-level privacy restrictions are not implemented. Finance and Marketing currently share read/report permissions because no marketing workflows exist. Demo retains the existing dashboard, summary, and order actions in memory; it has no SQL membership management.

`GET /organization/members` is limited to Owner/Admin. `POST /organization/members/<user_id>/role` is Owner-only, requires CSRF, targets an existing active membership in the current organization, and cannot demote the last active, unlocked Owner. Concurrent role administration is serialized by an organization lock. Invitations use separate endpoints below; no endpoint reactivates an existing inactive/revoked membership.

Migration 8 adds nullable `OrganizationMemberships.RoleName`, its trusted role foreign key, `Roles`, and `RolePermissions`. Only a sole legacy ClientUser mapped to its own organization is automatically Owner. Additional cross-organization memberships and ambiguous multi-account organizations remain unassigned. Existing membership status and all credential/order data remain unchanged. Founder backfill runs only when the role column is first introduced; reruns preserve assignments and fail on permission-policy drift. Later imports through migration 7 need explicit role review. New-business signup assigns Owner transactionally.

Read-only preflight for the already-confirmed disposable database, followed by migration (already applied locally):

```powershell
sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -d DukaanDesk_Test -b -Q "SELECT DB_NAME() AS TargetDatabase; SELECT COL_LENGTH('dbo.OrganizationMemberships','RoleName') AS ExistingRoleColumn; SELECT COUNT(*) AS AmbiguousFounderOrganizations FROM (SELECT SellerID FROM ClientUsers GROUP BY SellerID HAVING COUNT(*)<>1) D;"
sqlcmd -S "lpc:localhost\MSSQLSERVER01" -E -N -C -d DukaanDesk_Test -b -i 8_OrganizationRoles.sql
```

Review ambiguous founders manually; never infer ownership from username, email similarity, or earliest employee ID.

### Phase 2.4 employee invitations

Owners manage invitations at `/organization/members`. The existing explicit `members.roles` permission plus a SQL-revalidated Owner assignment is required for invitation creation/revocation and membership deactivation. Admin can view the roster but cannot manage invitations. Demo has no invitation access.

Workflow:

1. Owner supplies email and Admin/Operations/Finance/Marketing/Support role. Owner invitations are forbidden. Existing membership (including inactive/revoked) or a pending invitation returns 409 without changing role/status.
2. A 256-bit random token expires in 48 hours; SQL stores only its SHA-256 hash. The link carries the token in a URL fragment, not a logged query/path. The page clears the fragment and submits the token via CSRF-protected POST. Do not enable request-body logging on these endpoints.
3. Every recipient requests a separate 256-bit mailbox verification code, valid for 15 minutes. Only its hash is stored; resend is limited to once per minute per invitation and invalidates the old code. Even existing users need this code because legacy business signup does not verify email ownership.
4. Existing users sign in with the matching global email; fresh SQL identity/activity checks plus the code authorize acceptance. New users provide a unique username and matching 10–128-character password; hashed user creation, active membership, and invitation consumption commit together. No legacy seller/account is created for employees, and no identity merging occurs.
5. Accepted/revoked/expired tokens cannot be reused. Expiry uses SQL UTC time, is displayed immediately, and is persisted on attempted use, revocation, or replacement. No expiry worker is required. The inviting Owner must still be authorized when the token is used. Owner can deactivate membership, but cannot remove the last active unlocked Owner. Existing sessions lose access on their next protected request.

Delivery uses Python's standard-library SMTP with mandatory certificate-verified STARTTLS or implicit TLS (no new package). Both modes require TLS 1.2 or newer and hostname verification; there is no plaintext/downgrade option. See Phase 2.5 configuration below. Keep `DEV_INVITATION_LINKS` unset in shared environments. Delivery is synchronous: a message may arrive before a subsequent database commit or SMTP disconnect fails, in which case the new link/code is unusable. A durable outbox is future work.

Local development without an invitation-email transport:

```powershell
$env:APP_ENV = 'development'
$env:DEV_INVITATION_LINKS = 'true'
$env:APP_HOST = '127.0.0.1'
python -B app.py
```

Use the DB/session variables from the local runtime section above. The one-time invitation link is shown only for loopback requests with both flags set, clearly labeled development-only. It is not logged or retrievable later. **Acceptance remains blocked without SMTP verification delivery, for both existing and new users.** This is not an email-verification bypass. Do not enable the development flow behind a reverse proxy; proxy connections can appear loopback.

Migration 9 creates `OrganizationInvitations` with tenant/user/role foreign keys, constrained states/roles, unique token hashes, and one pending invitation per organization/email. To support employees without inventing legacy sellers, it makes `Users.LegacyClientUserID` nullable and transactionally replaces its old unique constraint with a filtered unique index on non-null links. Existing values, FK, and immutable-link trigger remain intact. Migration 7 now recognizes either legacy index form; reruns do not remap or merge employees.

Read-only preflight and migration for **the already-confirmed disposable database only** (migration is now applied locally):

```powershell
sqlcmd -S 'lpc:localhost\MSSQLSERVER01' -E -N -C -d DukaanDesk_Test -b -Q "SELECT DB_NAME() AS TargetDatabase; SELECT COUNT(*) AS Users FROM dbo.Users; SELECT OBJECT_ID('dbo.OrganizationInvitations','U') AS InvitationsTable; SELECT name,is_disabled,is_not_trusted FROM sys.foreign_keys WHERE parent_object_id=OBJECT_ID('dbo.Users'); SELECT LegacyClientUserID,COUNT(*) AS Mappings FROM dbo.Users WHERE LegacyClientUserID IS NOT NULL GROUP BY LegacyClientUserID HAVING COUNT(*)>1;"
sqlcmd -S 'lpc:localhost\MSSQLSERVER01' -E -N -C -d DukaanDesk_Test -b -i 9_OrganizationInvitations.sql
```

Stop if the target or ownership is uncertain, duplicate mappings exist, or the expected FK is disabled/untrusted. No production migration is authorized by these instructions.

### Phase 2.5 — SMTP setup and verification

Exact environment variables (read at send time; restart after changing the launching shell's environment):

- `SMTP_HOST`: required hostname/IP, without a URL scheme, credentials, or path.
- `SMTP_FROM`: required provider-authorized, bare ASCII email address; display names/address lists are not supported. Recipients must also be single bare ASCII mailboxes.
- `SMTP_SECURITY`: `starttls` (default) or `ssl` (implicit TLS).
- `SMTP_PORT`: integer 1–65535; default 587 for `starttls`, 465 for `ssl`. Follow your provider's TLS/port pairing.
- `SMTP_TIMEOUT`: integer 1–60 seconds, default 10; applies to socket operations, not the entire delivery transaction.
- `SMTP_USERNAME` and `SMTP_PASSWORD`: provide both for authentication, or omit both only for an explicitly authorized trusted relay. Use a provider-issued SMTP credential/app password where applicable; do not put credentials in Git, URLs, screenshots, or logs. OAuth-only SMTP authentication is not implemented.
- `APP_PUBLIC_URL`: required for emailed invitation links; a fixed HTTPS origin, e.g. `https://app.example.com`, without a path, query, fragment, or embedded credentials. It is never taken from an incoming Host header.

Missing/invalid configuration fails before SMTP connection; malformed port/timeout values are rejected rather than silently replaced. Authentication occurs only after verified TLS and successful EHLO. A refused sender/recipient/message, failed certificate, unsupported STARTTLS, timeout, or connection/authentication failure returns a safe HTTP 503 and rolls back the invitation/code transaction. No membership activates through a send failure. Logs contain only fixed failure categories (`configuration`, `authentication`, `tls-or-capability`, `rejected`, `timeout`, `unavailable`, `message-configuration`), never SMTP server responses, addresses, credentials, or message bodies. Never enable infrastructure request-body logging for invitation endpoints.

Example PowerShell setup, using your provider settings and an already-authorized HTTPS app origin:

```powershell
$env:SMTP_HOST = 'smtp.your-provider.example'
$env:SMTP_FROM = 'verified-sender@your-domain.example'
$env:SMTP_SECURITY = 'starttls'
$env:SMTP_PORT = '587'
$env:SMTP_TIMEOUT = '10'
$env:APP_PUBLIC_URL = 'https://your-app.example'
$smtpCredential = Get-Credential -Message 'Enter your provider SMTP credentials'
$env:SMTP_USERNAME = $smtpCredential.UserName
$env:SMTP_PASSWORD = $smtpCredential.GetNetworkCredential().Password
$env:DEV_INVITATION_LINKS = 'false'
# Keep the existing DB settings and stable SESSION_SECRET. HTTPS needs:
$env:SESSION_COOKIE_SECURE = 'true'
python -B -c "import app; app.smtp_configuration(); print('SMTP configuration valid; no network delivery tested')"
python -B app.py
```

For implicit TLS, set `SMTP_SECURITY=ssl` and `SMTP_PORT=465` (or your provider's explicit port). The example does not provision HTTPS or deploy the app. Configuration validation proves neither provider authentication nor inbox delivery. Environment variables hold secrets in process memory; use the deployment secret manager for a shared environment.

Manual browser verification — not yet performed:

1. Use an approved disposable test database with migration 9 already installed, a configured mail provider, and inboxes you control. Do not migrate/reset an existing database for this check. Open the configured HTTPS app as an Owner.
2. Invite a test recipient to a non-Owner role from Members. Check the actual inbox/spam folder; the UI saying “submitted” means SMTP server acceptance, not confirmed inbox delivery. Confirm the invitation URL uses the configured origin and the page removes its fragment.
3. In a separate browser profile, open the link and request verification. Confirm a second email arrives at the invited mailbox; the application must not display the code. New recipients register using that code; existing recipients sign in with the matching email, reopen the link, and enter the code to accept.
4. Confirm the expected organization/role appears. Reopen the consumed invitation: it must not activate another membership. A different signed-in email or missing/wrong code must not accept.
5. Use separate fresh test invitations to check Owner revocation, resend cooldown (60 seconds), replacement-code invalidation, and natural expiry (15-minute code / 48-hour invitation), without editing database timestamps. Non-Owners must not invite or revoke.
6. In an isolated test process, an unavailable SMTP host or rejected credentials must produce a safe 503, no new committed invitation/code, and no activated membership. Never paste credentials or codes into bug reports. Restore the test process configuration afterward.

### Latest verification — Phase 2.5 (2026-10-13)

- `python -B -m pytest tests/test_smtp.py tests/test_invitations.py -q -p no:cacheprovider`: **22 passed, 46 subtests passed**.
- Focused existing CSRF/RBAC/tenant/session regressions: **6 passed, 61 subtests passed**, 17 unrelated tests deselected. Command: `python -B -m pytest tests/test_app.py -q -p no:cacheprovider -k "post_without_csrf or each_role_permission or role_change_revalidated or forged_global or membership_revoked or switch_requires"`.
- All focused tests passed. SMTP and route database connections were mocked: tests cover both TLS modes/certificate settings, strict configuration, explicit recipient envelope, TLS-before-auth ordering, refusal/auth/timeout/disconnect failures, sanitized logging, hash-only persistence, rollback, consumed/expired tokens, cooldown, and missing/wrong-proof denial. Full suites and SQL integration were deliberately not rerun. No database was accessed or modified; no migration or new dependency was needed.
- All SMTP environment variables and `APP_PUBLIC_URL` were absent in the inspected process (only presence was checked). **Real email delivery, provider authentication, and manual browser verification remain untested.** Existing Phase 2.4 SQL results below are historical, not a new SQL verification claim.

### Historical verification — Phase 2.4 (2026-10-12)

- Offline suite: **29 passed, 77 subtests passed**. Final SQL-enabled full suite: **47 passed, 101 subtests passed** (29 offline + 18 SQL tests). `pip check` and `git diff --check` passed. An initial offline failure was the old legacy-only SQL-shape assertion; it was updated to verify the backward-compatible global/legacy lookup. No SQL test failures occurred.
- Read-only preflight confirmed `DukaanDesk_Test`, 60 users, 67 memberships, trusted legacy FKs, and no invitations table. Migration 9 was applied there only and rerun idempotently; original row values were compared in memory and preserved. Earlier migrations 7/8 remain compatible.
- Real SQL coverage includes new/legacy identity login, all role boundaries, hashed tokens, matching and mismatched email, separate mailbox-code enforcement, expiry/replacement, replay and concurrent acceptance, duplicate pending/existing membership rejection, revocation, cross-tenant targets, issuer authority changes, deactivation, last-Owner protection, and employee lockout. Existing MVP order/dashboard/message-log tests still pass.
- SMTP was mocked for verification tests; no real email was sent. Mail configuration is absent locally, so real recipient acceptance remains blocked until SMTP is configured. Template rendering was tested; browser visual QA, external delivery, and production deployment were not verified.
- Final disposable counts: 107 sellers/organizations/legacy accounts, 115 global users (8 without legacy links), 136 memberships, 91 buyers, 181 orders, 290 message logs, and 27 invitations (13 Accepted, 3 Expired, 8 Pending, 3 Revoked). All pre-existing rows/role assignments/invitations survived the test runs. No missing legacy mappings, disabled/untrusted FKs, or disabled/untrusted invitation checks; the immutable user-link trigger remains enabled.
- No user-data deletion, database reset, CODManager/system-database operation, dependency installation, Git commit/push/pull/reset, or deployment occurred. New uniquely named synthetic test rows remain deliberately.

### Historical verification — Phase 2.3 (2026-10-12)

- Full SQL-enabled suite: **33 passed, 72 subtests passed** (23 offline tests and 10 guarded SQL tests). No test failures occurred. `git diff --check` passed.
- Read-only preflight found 42 sole-account founder mappings, three additional memberships, and zero ambiguous founder organizations. Migration 8 assigned 42 Owners and left the three additional memberships unassigned; membership status and existing accounts/orders were preserved.
- Tested all six roles against dashboard, summary, decisions, delivery, switching, roster viewing, and role assignment. Also tested role changes without re-login, roleless denial, cross-tenant access, last-owner protection, malformed role requests, immutable existing roles on rerun, and permission-policy drift rejection.
- First-run migration verification used an uncommitted two-employee organization: neither historical employee became Owner. The new fixture and DDL were rolled back before the actual additive migration; no existing data was deleted or reset.
- Full original row comparisons preserved pre-existing operational and identity data. Final disposable database: 60 sellers/organizations/legacy accounts/global users, 67 memberships, 73 buyers, 125 orders, 196 logs. Role counts: 58 Owner, 2 Admin, 2 Operations, 5 unassigned. The unassigned rows include preserved additional memberships and later locked-account import fixtures; no automatic role escalation occurred.
- Only `DukaanDesk_Test` was queried/modified. Its membership-role foreign key is enabled and trusted. Existing unrelated workspace edits were preserved. No deployment or browser visual QA was performed.

### Historical verification — Phase 2.2 (2026-10-12)

- Complete SQL-enabled suite: 28 passed and 10 subtests passed (21 offline tests and 7 SQL tests).
- Initial read-only preflight: 22 legacy accounts, zero duplicate email groups, zero missing organizations. All 22 accounts were imported with their credential and lockout values preserved.
- SQL tests verify migration idempotence, duplicate-email rollback, locked legacy account backfill, legacy session upgrade, active switching, rejected inactive/revoked memberships, disabled-user rejection, and the existing authentication/order/reporting workflows.
- Full original rows in all six legacy tables, plus pre-existing global users/memberships on subsequent runs, were compared in memory and preserved. No system database or `CODManager` operations were performed in Phase 2.2.
- Final disposable counts: 35 sellers/organizations/legacy accounts/global users, 37 memberships (35 active, 2 revoked), 48 buyers, 60 orders, 89 logs. Zero missing user mappings, ambiguous emails, or disabled/untrusted identity foreign keys.
- Browser visual QA and production deployment remain unverified.

### Historical Phase 2.1 verification (2026-10-12)

- Offline suite: 18 passed, 3 SQL tests safely skipped, and 5 invalid-amount subtests passed.
- SQL-enabled complete suite: 21 passed, including 3 real SQL integration tests and 5 invalid-amount subtests.
- `python -m py_compile app.py tests/test_app.py tests/test_sql_integration.py`: passed.
- `python -m pip check`: no broken requirements.
- Flask test-client smoke check: login, signup, and storefront pages returned HTTP 200; protected pages redirected; a POST without CSRF returned HTTP 400; security headers were present.
- SQL Server 17.0 Standard Developer Edition at `localhost\MSSQLSERVER01` was verified with Windows Authentication, ODBC Driver 18, encrypted transport, and trusted local certificate.
- `DukaanDesk_Test` contains six application tables, including `Organizations`, plus the pending view and both enabled triggers. `CODManager` was not created or modified.
- Before the Phase 2.1 migration, the disposable database contained 18 sellers/users, 28 buyers, 34 orders, and 52 logs. `6_Organizations.sql` backfilled 18 mappings, and a second run inserted zero rows. Immediate post-migration fingerprints for all legacy tables were unchanged.
- Real SQL tests passed for organization creation during signup, authenticated mapping, complete backfill, trusted one-to-one constraints, immutable mapping enforcement, cross-organization read/write denial, and ignored client-supplied tenant IDs, in addition to the prior signup/login/lockout/order/message/summary/concurrency coverage.
- The final audit preserved every original row fingerprint and found zero missing/duplicate organization mappings and zero cross-seller orders. Integration tests added only uniquely named synthetic rows; seed/reset scripts and cleanup deletes were not run.

## Known limitations

- SQL integration has been verified only on the local disposable `DukaanDesk_Test` database; production deployment and other SQL Server environments remain unverified.
- Passwords left as legacy plaintext remain so until that user successfully logs in; a forced reset/migration flow is still needed before real launch.
- Account unlock is manual; there is no password reset, general account-email verification, MFA, or administrative recovery workflow. Invitation acceptance has its own mailbox verification; business signup remains unverified.
- Public order submission has no rate limiting, bot protection, webhook authentication, product catalog, inventory, taxes, shipping calculation, or payment integration.
- Flask's signed cookie session is used; there is no shared server-side session store.
- Invited global users have no legacy account link; existing links remain immutable. Each organization still maps to one seller/domain. Membership reactivation and ownerless-organization recovery require a separately authorized administrative process. Role-change/deactivation audit history, field-level privacy, connectors, lifecycle, platform administration, and subscriptions remain future work. Last-owner protection applies to application role/deactivation endpoints; unrestricted database administrators can bypass it.
- SMTP delivery is not configured or externally verified locally. Existing users with no usable active organization cannot currently log in to accept; they need a separately reviewed recovery flow. Invitation abuse controls are limited to high-entropy tokens and per-invitation verification resend cooldown; account/IP quotas and durable mail delivery are launch blockers.

See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for the detailed technical handoff and [ROADMAP.md](ROADMAP.md) for priorities.
