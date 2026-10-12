# DukaanDesk

DukaanDesk is a server-rendered Flask and Microsoft SQL Server MVP for cash-on-delivery order operations. A seller can onboard one business/organization, expose a domain-scoped order form, review incoming orders, confirm or cancel them, record delivery outcomes, and view twelve-month summaries.

The current code is a single-store-per-seller MVP. The intended product is a multi-tenant B2B SaaS that connects existing Shopify, WooCommerce, and custom storefronts, supports employees and roles, and gives a platform super admin subscription controls. Those capabilities are future work and are not implemented here.

## Current features

- Seller signup and session-based login.
- Global user identities and active organization memberships, with a small organization selector for users who have access to multiple organizations.
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
public/_organization_selector.html  Shared selector for multiple active memberships
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

`1_Schema.sql` refuses to continue if `CODManager` already exists. It no longer drops a database. The fresh schema includes `Organizations`; `2_Logic.sql` installs both the order-log trigger and organization-identity protection.

For an existing pre-Phase-2.1 database, back it up and review the scripts before running `5_Migration.sql`, followed by `6_Organizations.sql`, then `7_UsersMemberships.sql`. For a Phase 2.1 database, only migration 7 is new. Stop application writes while migrating and update all application processes together: older code writes only the legacy authentication table.

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

The integration suite has a hard safety gate: it skips unless `RUN_SQL_INTEGRATION_TESTS=1` and `DB_NAME` is exactly `DukaanDesk_Test`; it also verifies `DB_NAME()` before writing. It applies/reruns migration 7, creates uniquely named synthetic rows, and verifies full pre-existing row values in memory without printing credentials. Duplicate-email rollback fixtures can leave identity-number gaps. No cleanup deletes run. Membership provisioning/revocation in these tests is trusted fixture SQL, not a public app feature.

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

Login keeps the existing email/username/password form. The default organization is the legacy seller organization if active, otherwise another active membership. The selector appears only with multiple active memberships. Revoked/inactive accounts or active sessions whose selected membership is no longer active must sign in again; no self-service membership creation exists. "Active" means a verified database membership, not verified email ownership.

### Latest verification status — Phase 2.2 (2026-10-12)

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
- Account unlock is manual; there is no password reset, email verification, MFA, or administrative recovery workflow.
- Public order submission has no rate limiting, bot protection, webhook authentication, product catalog, inventory, taxes, shipping calculation, or payment integration.
- Flask's signed cookie session is used; there is no shared server-side session store.
- Global users can belong to multiple organizations, but each user retains a required one-to-one legacy account link and each organization still maps to one seller/domain. All active members have the existing seller operational permissions; roles are not implemented. Additional memberships require a separately authorized administrative process. Invitations, connected stores, RBAC, lifecycle, administration, and subscriptions remain future work.

See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for the detailed technical handoff and [ROADMAP.md](ROADMAP.md) for priorities.
