# DukaanDesk Project Context

Last audited: 2026-10-12

This document is the implementation handoff for future developers and AI assistants. Treat the code and migrations as authoritative if this file later becomes stale.

## Product boundary

Current MVP: one seller business with one unique domain per signup, one or more historical `ClientUsers` rows per seller at the database level, domain-scoped public COD order intake, seller order decisions, delivery outcomes, and reporting.

Long-term vision: a multi-tenant B2B SaaS where each business can connect multiple existing Shopify, WooCommerce, or custom stores; invite employees with role-based permissions; operate orders and analytics across those stores; and be managed by a platform super admin with subscription/billing controls. None of the connector, multi-store, RBAC, super-admin, or subscription architecture exists yet. Do not describe it as implemented.

## Runtime architecture

```text
Browser
  ├─ public seller forms and Jinja-rendered dashboard
  └─ public domain-scoped order form
          │ HTTP / Flask signed-cookie session + CSRF
          ▼
app.py (single Flask process)
  ├─ authentication and account lockout
  ├─ validation and order state rules
  ├─ seller-scoped SQL queries/mutations
  ├─ KPI and 12-month grouping in Python
  └─ optional isolated in-memory demo adapter
          │ parameterized pyodbc queries
          ▼
Microsoft SQL Server / CODManager
  ├─ Sellers ── ClientUsers
  ├─ Sellers ── Buyers ── Orders
  ├─ Orders ── MessageLogs
  ├─ vw_PendingConfirmations
  └─ trg_AutoLogCreation
```

There is no JSON API, SPA, background worker, queue, cache, external identity provider, product service, connector service, or messaging provider. Pages are server-rendered. The JavaScript footprint is effectively absent; shared presentation is in `public/styles.css`.

## Source files

- `app.py`: all Flask configuration, security helpers, database access, demo mode, business logic, and routes.
- `public/login.html`: seller login and demo-mode notice.
- `public/signup.html`: first seller/business account creation.
- `public/dashboard.html`: active pending/confirmed orders, search, actions, delivery outcomes, KPIs.
- `public/summary.html`: last-12-month delivered/cancelled/returned groups and KPIs.
- `public/store.html`: public COD order form routed by seller domain.
- `public/index.html`: legacy navigation page; `/` currently redirects to login/dashboard instead of rendering it.
- `public/styles.css`: responsive shared styles; imports Google Fonts over the network.
- `tests/test_app.py`: database-free unit/route tests using fake pyodbc connections.
- `1_Schema.sql`: fresh `CODManager` installer. It aborts when the database already exists.
- `2_Logic.sql`: creates/updates the pending view and a multi-row-safe insert trigger.
- `3_DataTesting.sql`: idempotent local seed; it does not delete existing rows.
- `4_Reports.sql`: delivered-revenue and message audit queries.
- `5_Migration.sql`: additive, transactional hardening for an existing database. It aborts on inconsistent rows.
- `reset.sql`: manual development query that unlocks user 1. It is not part of setup.
- `checking.sql`: pre-existing user-owned ad-hoc seller query. It is not part of setup.
- `package.json` / `package-lock.json`: legacy Node dependencies are unused. `npm start` and `npm test` now delegate to Python for convenience.

## Flask routes

- `GET /`: redirects authenticated sessions to `/dashboard`, otherwise `/login`.
- `GET|POST /login`: authenticates by seller email plus globally unique username and password. Successful login rotates the session and establishes an eight-hour permanent session.
- `GET|POST /signup`: validates and creates a new `Sellers` row and first `ClientUsers` row in one transaction. Existing domains and WhatsApp numbers are rejected; unauthenticated creation of extra users for a seller is intentionally disallowed.
- `POST /logout`: clears the session.
- `GET /dashboard`: requires authentication; loads only `session.user.seller_id`, then displays operational orders whose state is pending confirmation or confirmed/awaiting delivery.
- `GET /summary`: requires authentication; loads all seller-scoped orders and groups terminal outcomes over the latest twelve calendar months.
- `POST /orders/<order_id>/action`: requires authentication; changes only this seller's `Pending`/null-delivery order to `Confirmed`/`Pending` or `Cancelled`/null.
- `POST /orders/<order_id>/status`: requires authentication; changes only this seller's `Confirmed`/`Pending` order to `Delivered` or `Returned by buyer`.
- `GET /store` and `GET /store/<domain_name>`: renders public order intake.
- `POST /store-order`: validates buyer and amount fields, resolves the seller by normalized domain, reuses a buyer by `(SellerID, Phone)`, and creates the next seller-relative order number.
- `GET /login.html`, `/signup.html`, `/dashboard.html`, `/summary.html`, `/store.html`: compatibility redirects.
- `/static/<path>`: Flask static handler for files under `public/`.

All POST routes require the per-session hidden `csrf_token`. State-changing seller queries contain both `OrderID` and `SellerID` and enforce the expected current state in the `WHERE` clause.

## Database model

### Sellers

Business identity and current MVP tenant boundary: `SellerID`, `BusinessName`, unique `WhatsAppNumber`, unique `Email`, and unique normalized `DomainName`.

### ClientUsers

Portal identity linked to `SellerID`: globally unique `Username`, `PasswordHash`, failed-attempt count, lock flag, last-failure timestamp, and creation timestamp. New values are Werkzeug `scrypt` hashes. When a legacy plaintext value matches during login, it is replaced with a hash inside the successful-login update.

The current UI creates only the first user for a new seller. A secure invitation and RBAC workflow is intentionally deferred.

### Buyers

Seller-scoped customer profile: global `BuyerID`, `SellerID`, name, phone, address, and `SellerBuyerNo`. Unique constraints cover `(SellerID, SellerBuyerNo)`, `(SellerID, Phone)`, and `(SellerID, BuyerID)`.

### Orders

Global `OrderID`, seller and buyer foreign keys, seller-relative `SellerOrderNo`, snapshot buyer name/address, positive decimal amount, order status, delivery status, and timestamp. The composite `(SellerID, BuyerID)` foreign key prevents an order from referencing another seller's buyer.

State model:

```text
Pending + null delivery
  ├─ confirm ──> Confirmed + Pending delivery
  │                 ├─> Confirmed + Delivered
  │                 └─> Confirmed + Returned by buyer
  └─ cancel ──> Cancelled + null delivery
```

The app rejects reverse or repeated transitions. The fresh schema and migration add an equivalent state-consistency check.

### MessageLogs

Weak child entity keyed by `(LogID, OrderID)`. The trigger logs initial order creation. Flask logs successful seller order and delivery transitions in the same database transaction as the state change. No WhatsApp message is actually sent.

### View and trigger

`vw_PendingConfirmations` joins pending orders to sellers and seller-matched buyers. `trg_AutoLogCreation` uses an `INSERT ... SELECT FROM inserted`, so multi-row inserts create one message log per order.

## Main workflows

### Signup

1. Normalize email/domain and validate field lengths/formats plus a 10-character minimum password.
2. Reject an existing domain or WhatsApp number. Database unique constraints also guard races and email/username duplication.
3. Insert seller and scrypt-hashed portal user in one transaction.
4. Rotate into an authenticated seller session.

### Login

1. Find `ClientUsers` joined to `Sellers` using username and seller email.
2. Reject locked accounts; increment and persist failures up to the three-attempt lock.
3. Verify a recognized Werkzeug hash, or constant-time compare a legacy plaintext value.
4. Upgrade a successfully matched legacy value to scrypt and clear failures.
5. Clear/rotate the Flask session, record tenant identity, and issue a new CSRF token.

If the database operation raises and explicit demo mode is configured, only matching configured demo credentials can open a demo session. Invalid database credentials do not fall through to demo mode. Demo data is returned only when the authenticated session has `is_demo=true`.

### Public order intake

1. Validate normalized domain, lengths, and a finite decimal amount from 0.01 through 99,999,999.99.
2. Open a transaction and lock the seller/buyer/order number ranges with SQL Server `UPDLOCK, HOLDLOCK` hints.
3. Reuse a buyer by seller plus phone, otherwise allocate a seller-relative buyer number.
4. Allocate a seller-relative order number and insert a pending order.
5. The trigger creates the initial message log; commit everything together.

### Dashboard/reporting

The dashboard query joins `Orders`, `Sellers`, and `Buyers` and always filters by seller ID. Search is performed in Python over the seller-scoped result. Delivered revenue includes only `DeliveryStatus='Delivered'`. The summary uses order creation month—not delivery completion month, because no completion timestamp exists.

## Security decisions implemented

- Parameterized pyodbc values for all application queries.
- ODBC values brace-escaped when building the connection string.
- Encrypted database transport and certificate verification default on; local self-signed use must be explicit.
- SQL authentication via environment variables or trusted authentication when credentials are absent.
- Password hashing and transparent legacy upgrade.
- CSRF protection on all POST routes.
- Session fixation mitigation, HTTP-only/Lax cookies, optional Secure flag, eight-hour lifetime, and no-store responses for authenticated pages.
- `X-Content-Type-Options`, `X-Frame-Options`, referrer, permissions, and HTTPS HSTS headers.
- One MiB request limit.
- Server-side validation matching database column lengths and decimal bounds.
- Tenant-scoped reads/writes plus database-level seller/buyer consistency.
- Explicit demo opt-in with environment-defined password and no hard-coded fallback credential.
- Flask debugger disabled unless explicitly requested.

## Configuration and dependencies

Runtime Python dependencies are Flask, pyodbc, and Werkzeug. Flask/Jinja handles rendering and signed-cookie sessions. SQL Server ODBC Driver 18 is an operating-system dependency and is not installed by pip.

Important environment variables are documented in `README.md`. `SESSION_SECRET` must be stable and secret for any shared environment. `SESSION_COOKIE_SECURE=true` is required behind HTTPS. SQL-authenticated Codespaces need `DB_SERVER`, `DB_USERNAME`, and `DB_PASSWORD`; trusted authentication is mainly for Windows/local SQL Server.

## Verification status

Verified offline on 2026-10-12:

- `python -m py_compile app.py tests/test_app.py tests/test_sql_integration.py`.
- `python -m pytest -q -p no:cacheprovider`: 16 passed, 2 guarded SQL tests skipped, and 5 invalid-amount subtests passed.
- Public GET pages render; protected pages redirect; missing CSRF receives HTTP 400; security headers are present.
- `python -m pip check` reported no broken requirements, and `git diff --check` passed.

Verified with SQL Server on 2026-10-12:

- SQL Server 17.0 Standard Developer Edition at `localhost\MSSQLSERVER01`, using Windows Authentication, ODBC Driver 18, `DB_ENCRYPT=true`, and `DB_TRUST_SERVER_CERTIFICATE=true`.
- A read-only master query confirmed zero non-system databases and that `DukaanDesk_Test` was absent. The guarded schema was adapted in memory to create only `DukaanDesk_Test`; `CODManager` remained absent.
- Fresh setup created five user tables, `vw_PendingConfirmations`, and `trg_AutoLogCreation` with zero initial rows. Neither `3_DataTesting.sql` nor `reset.sql` was executed.
- The SQL-enabled suite passed 18 tests total: 16 offline tests plus two guarded real-database tests. It verified signup, scrypt password storage, hashed login, real legacy-plaintext upgrade, persistent three-attempt lockout, public order creation, confirmation, cancellation, delivery, seller isolation, dashboard/summary output, exact trigger/action/delivery log messages, and four concurrent seller-relative buyer/order allocations.
- Read-only migration preflight on populated synthetic data found zero invalid order states, zero cross-seller orders, and zero legacy credential values. The non-destructive `5_Migration.sql` completed successfully after in-memory database-name substitution; the tenant foreign key and all four order checks remained enabled and trusted.
- Final database audit showed only `DukaanDesk_Test` outside the four system databases. Its objects were healthy; integration tests intentionally left only uniquely named synthetic rows and performed no cleanup deletes.

Not verified in the current environment:

- Linux/Codespace ODBC driver installation and SQL connectivity; this verification used the local Windows instance and shared-memory `sqlcmd` transport.
- HTTPS/proxy behavior, multi-process session behavior, production WSGI serving, or deployment.
- Browser visual QA beyond template rendering.

## Continuation guidance

1. Preserve uncommitted user changes. At audit time, branding edits in all HTML pages, `checking.sql`, and a tracked `.pyc` modification predated the security work.
2. Do not run `reset.sql`, delete rows, drop databases, or execute a migration without the user's confirmation and a backup.
3. Before SQL verification, inspect the target and run read-only consistency queries corresponding to the preflight checks in `5_Migration.sql`.
4. Keep current MVP fixes separate from the future multi-store/RBAC/subscription redesign.
5. Any real connector work needs signed webhook ingestion, idempotency keys, provider credential encryption, store-level tenant boundaries, retry/dead-letter handling, and reconciliation before it can be called reliable.
6. Update this file, `README.md`, tests, and `ROADMAP.md` whenever routes, state rules, schema, or verified runtime status changes.

## Phase 2.1 gate

Status: **ready to begin Phase 2.1 design and isolated development from the verified MVP baseline**. The disposable-database gate now covers signup, hashed and legacy-upgrade login, lockout, order creation, both order decisions, delivery outcomes, tenant isolation, concurrent numbering, the insert trigger, message-log transactions, summaries, and migration compatibility. This is not production-launch readiness: the remaining P0 identity, abuse prevention, runtime/operations, and independent security-review work still applies.
