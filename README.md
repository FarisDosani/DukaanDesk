# DukaanDesk

DukaanDesk is a server-rendered Flask and Microsoft SQL Server MVP for cash-on-delivery order operations. A seller can onboard one business/organization, expose a domain-scoped order form, review incoming orders, confirm or cancel them, record delivery outcomes, and view twelve-month summaries.

The current code is a single-store-per-seller MVP. The intended product is a multi-tenant B2B SaaS that connects existing Shopify, WooCommerce, and custom storefronts, supports employees and roles, and gives a platform super admin subscription controls. Those capabilities are future work and are not implemented here.

## Current features

- Seller signup and session-based login.
- Werkzeug `scrypt` password hashes for new users; a successful legacy plaintext login upgrades that row in place.
- Lockout after three failed database or demo login attempts.
- Explicit, opt-in, in-memory demo mode; it is off by default and never silently exposes demo data to database users.
- Public order entry at `/store/<seller-domain>`.
- Immutable organization tenant IDs with a one-to-one mapping to legacy sellers.
- Organization- and seller-scoped dashboard queries and mutations; tenant IDs are resolved server-side and are never accepted from forms.
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

`1_Schema.sql` refuses to continue if `CODManager` already exists. It no longer drops a database. The fresh schema includes `Organizations`; `2_Logic.sql` installs both the order-log trigger and organization-identity protection.

For an existing pre-Phase-2.1 database, back it up and review the scripts before running `5_Migration.sql`, followed by `6_Organizations.sql`. Both migrations are additive/transactional. `6_Organizations.sql` creates exactly one organization for every unmapped seller, refuses an incompatible pre-existing table, and can be re-run safely. The updated application requires this migration because login and tenant-scoped order access join `Organizations`.

No database script is run automatically by the Flask application. `reset.sql` changes account lock state and is only a manual development helper.

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

The integration suite has a hard safety gate: it skips unless `RUN_SQL_INTEGRATION_TESTS=1` and `DB_NAME` is exactly `DukaanDesk_Test`; it also verifies `DB_NAME()` before writing. It creates uniquely named synthetic rows and does not delete existing rows.

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

### Latest verification status (2026-10-12)

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
- Organization identity now exists, but authenticated membership still uses the legacy `ClientUsers.SellerID` link and every organization still maps one-to-one to one seller/business/domain. Connected stores, invitations, RBAC, lifecycle/soft deletion, platform administration, and subscriptions are roadmap items.

See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for the detailed technical handoff and [ROADMAP.md](ROADMAP.md) for priorities.
