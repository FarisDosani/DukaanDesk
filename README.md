# DukaanDesk

DukaanDesk is a server-rendered Flask and Microsoft SQL Server MVP for cash-on-delivery order operations. A seller can onboard one business, expose a domain-scoped order form, review incoming orders, confirm or cancel them, record delivery outcomes, and view twelve-month summaries.

The current code is a single-store-per-seller MVP. The intended product is a multi-tenant B2B SaaS that connects existing Shopify, WooCommerce, and custom storefronts, supports employees and roles, and gives a platform super admin subscription controls. Those capabilities are future work and are not implemented here.

## Current features

- Seller signup and session-based login.
- Werkzeug `scrypt` password hashes for new users; a successful legacy plaintext login upgrades that row in place.
- Lockout after three failed database or demo login attempts.
- Explicit, opt-in, in-memory demo mode; it is off by default and never silently exposes demo data to database users.
- Public order entry at `/store/<seller-domain>`.
- Seller-scoped buyers, order numbers, dashboard queries, and mutations.
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

`1_Schema.sql` refuses to continue if `CODManager` already exists. It no longer drops a database. For an existing database, back it up, review the preflight rules, then run `5_Migration.sql` manually. The migration is transactional and rolls back if it finds invalid state or cross-seller order/buyer rows. Re-run `2_Logic.sql` afterward to install the corrected set-based trigger.

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
python -m py_compile app.py tests/test_app.py
python -m pip check
```

## Known limitations

- SQL Server-backed end-to-end behavior has not been verified in the current environment because no database endpoint/configuration is available.
- Passwords left as legacy plaintext remain so until that user successfully logs in; a forced reset/migration flow is still needed before real launch.
- Account unlock is manual; there is no password reset, email verification, MFA, or administrative recovery workflow.
- Public order submission has no rate limiting, bot protection, webhook authentication, product catalog, inventory, taxes, shipping calculation, or payment integration.
- Flask's signed cookie session is used; there is no shared server-side session store.
- Current tenancy is one seller/business/domain per signup. Connected stores, employees/RBAC, platform administration, and subscriptions are roadmap items.

See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for the detailed technical handoff and [ROADMAP.md](ROADMAP.md) for priorities.
