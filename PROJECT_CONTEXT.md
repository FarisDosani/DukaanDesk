# DukaanDesk Project Context

Last audited: 2026-10-12

This document is the implementation handoff for future developers and AI assistants. Treat the code and migrations as authoritative if this file later becomes stale.

## Product boundary

Current MVP: immutable `Organizations` tenants mapped one-to-one to legacy sellers, global `Users` with active organization memberships, one unique domain per signup, domain-scoped public COD order intake, seller order decisions, delivery outcomes, and reporting. A user can switch among existing active memberships; there is no membership provisioning UI or API.

Long-term vision: businesses connect multiple Shopify, WooCommerce, or custom stores and invite employees, with platform administration and subscriptions. Global users, memberships, and six organization-scoped roles are implemented; invitations, connectors, multiple stores, super-admin, and billing are not.

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
  ├─ organization + legacy-seller-scoped SQL queries/mutations
  ├─ KPI and 12-month grouping in Python
  └─ optional isolated in-memory demo adapter
          │ parameterized pyodbc queries
          ▼
Microsoft SQL Server / CODManager
  ├─ Organizations ── Sellers ── ClientUsers
  ├─ Users ── OrganizationMemberships ── Organizations
  ├─ OrganizationMemberships ── Roles ── RolePermissions
  ├─ Users ── one-to-one legacy ClientUsers mapping
  ├─ Sellers ── Buyers ── Orders
  ├─ Orders ── MessageLogs
  ├─ vw_PendingConfirmations
  ├─ trg_AutoLogCreation
  ├─ trg_Organizations_ImmutableIdentity
  └─ trg_Users_ImmutableIdentity
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
- `tests/test_sql_integration.py`: guarded real-SQL migration, identity, membership, and MVP tests; captures pre-existing row values without logging secrets.
- `public/_organization_selector.html`: shared CSRF-protected selector, displayed only for multiple active memberships.
- `public/members.html`: Owner/Admin roster; Owner-only role-assignment controls for existing active memberships.
- `1_Schema.sql`: fresh `CODManager` installer. It aborts when the database already exists.
- `2_Logic.sql`: creates/updates the pending view and a multi-row-safe insert trigger.
- `3_DataTesting.sql`: idempotent local seed; it does not delete existing rows.
- `4_Reports.sql`: delivered-revenue and message audit queries.
- `5_Migration.sql`: additive, transactional hardening for an existing database. It aborts on inconsistent rows.
- `6_Organizations.sql`: additive, idempotent organization migration. It backfills one tenant per seller and installs immutable-identity protection.
- `7_UsersMemberships.sql`: additive transactional global identity/membership migration; must run in an explicitly selected application database after Phase 2.1 (also required after a fresh schema).
- `8_OrganizationRoles.sql`: additive role catalog/grants and membership RoleName foreign key, with conservative founder backfill; required after migration 7 for both fresh and existing installations.
- `reset.sql`: legacy-only unlock helper; no longer suitable for current authentication, whose authority is `Users`.
- `checking.sql`: pre-existing user-owned ad-hoc seller query. It is not part of setup.
- `package.json` / `package-lock.json`: legacy Node dependencies are unused. `npm start` and `npm test` now delegate to Python for convenience.

## Flask routes

- `GET /`: redirects authenticated sessions to `/dashboard`, otherwise `/login`.
- `GET|POST /login`: retains email/username/password login, authenticates against `Users`, and chooses an active membership (preferring the legacy seller organization). Successful login rotates the session and establishes an eight-hour permanent session.
- `GET|POST /signup`: atomically creates seller, organization, legacy account, global user, and initial active membership. Existing domains/WhatsApp numbers and duplicate global emails/usernames are rejected. It cannot attach a user to an existing organization.
- `POST /organizations/switch`: validates a UUID selection against the requesting user's freshly queried active memberships, then rotates session and CSRF state. Unauthorized selections receive 403; malformed IDs receive 400. No membership is created.
- `GET /organization/members`: requires `members.view`; returns only the current organization's roster.
- `POST /organization/members/<user_id>/role`: requires `members.roles`; assigns an existing role to an active membership in the current organization. Unknown role = 400, unauthorized = 403, absent/inactive/cross-tenant target = 404, last-owner demotion = 409. Organization-level SQL locks serialize administration and preserve an active, unlocked Owner through this endpoint.
- `POST /logout`: clears the session.
- `GET /dashboard`: requires authentication; loads only orders matching both the signed server-derived organization context and its legacy seller ID, then displays operational orders whose state is pending confirmation or confirmed/awaiting delivery.
- `GET /summary`: requires authentication; loads all organization-and-seller-scoped orders and groups terminal outcomes over the latest twelve calendar months.
- `POST /orders/<order_id>/action`: requires authentication; changes only this organization/seller's `Pending`/null-delivery order to `Confirmed`/`Pending` or `Cancelled`/null.
- `POST /orders/<order_id>/status`: requires authentication; changes only this organization/seller's `Confirmed`/`Pending` order to `Delivered` or `Returned by buyer`.
- `GET /store` and `GET /store/<domain_name>`: renders public order intake.
- `POST /store-order`: validates buyer and amount fields, resolves the seller by normalized domain, reuses a buyer by `(SellerID, Phone)`, and creates the next seller-relative order number.
- `GET /login.html`, `/signup.html`, `/dashboard.html`, `/summary.html`, `/store.html`: compatibility redirects.
- `/static/<path>`: Flask static handler for files under `public/`.

All POST routes require the per-session hidden `csrf_token`. Protected requests verify an active, unlocked global user and active selected membership in SQL every time. State-changing order queries additionally contain `OrderID`, `SellerID`, `OrganizationID`, active global user/membership checks, and expected current state. The switch form's organization ID is only a selection; order forms cannot override tenant context.

## Database model

### Sellers

Legacy operational identity: `SellerID`, `BusinessName`, unique `WhatsAppNumber`, unique `Email`, and unique normalized `DomainName`. Existing buyer/order relationships remain attached to this key for compatibility.

### Organizations

Immutable SaaS tenant identity: GUID `OrganizationID`, unique `LegacySellerID`, `OrganizationName`, and `CreatedAt`. The unique key and trusted foreign key enforce exactly zero-or-one organization per seller at schema level; the migration backfills every seller, making it exactly one in the deployed database. `trg_Organizations_ImmutableIdentity` rejects key remapping and deletion. `OrganizationName` is initialized from `BusinessName` but is not yet synchronized if legacy seller data is edited. Tenant lifecycle/soft deletion is not implemented.

### ClientUsers

Legacy account linked to `SellerID`: globally unique `Username`, `PasswordHash`, failed-attempt count, lock flag, last-failure timestamp, and creation timestamp. Rows and keys remain intact for compatibility. Authentication now reads `Users`; app login updates mirror credential and lockout fields back into this table in the same transaction. Legacy-only updates no longer change the authoritative credential.

Signup creates only the first user for a new seller. Role assignment to existing active memberships is implemented; secure invitations and membership provisioning remain deferred.

### Users and OrganizationMemberships

`Users.UserID` is the global integer identity. `LegacyClientUserID` is a required unique foreign key to `ClientUsers.UserID`; a trigger rejects identity/remapping updates. Unique `Username` and computed persisted `NormalizedEmail` (trim/lowercase) prevent duplicate global identities. PasswordHash, FailedAttempts, IsLocked, LastFailedAt, and CreatedAt are copied exactly at migration. `IsActive` can disable the global account. Authentication uses Werkzeug hashes with the existing successful-login legacy plaintext upgrade and three-attempt lockout; a locked SQL read serializes login failure updates.

`OrganizationMemberships` has composite primary key `(UserID, OrganizationID)`, non-cascading user/organization foreign keys, CreatedAt, constrained Status (`Active`, `Inactive`, `Revoked`), and nullable RoleName referencing Roles. The default status is Inactive; migration 7 and signup explicitly create Active membership. Active membership alone no longer authorizes protected operations: a corresponding role grant is required. Email verification is still absent.

Migration 7 runs without a `USE` directive and refuses system databases. Preflight aborts on ambiguous normalized legacy seller emails, missing organizations, invalid failure counts, partial identity schema, or missing/untrusted expected constraints. One global user is created per unmapped legacy account, with its legacy organization membership. It never merges by email. Multiple legacy users sharing a business email require manual identity/ownership resolution before migration; this deployment had zero such groups. Reruns preserve existing user state and memberships, including revoked or removed memberships; no automatic reactivation occurs. Stop old application processes during migration because older versions write only ClientUsers.

### Roles and explicit permissions (Phase 2.3)

Roles are a shared catalog of six fixed names; authority is scoped by each organization's membership assignment. RolePermissions stores explicit grants with a composite primary key and constrained permission names. No global user role exists. `require_permission` wraps authentication and denies absent grants; `resolve_legacy_organization_context` reloads the role and grants from SQL every protected request. `g.permissions` is request-local; session/form role claims cannot grant access. Order reads/writes and roster reads also check RolePermissions in SQL. The role-change endpoint rechecks the actor inside its locked transaction.

- Owner: dashboard.view, summary.view, orders.decide, orders.delivery, organizations.switch, members.view, members.roles.
- Admin: all Owner grants except members.roles.
- Operations: dashboard.view, orders.decide, orders.delivery, organizations.switch.
- Finance and Marketing: dashboard.view, summary.view, organizations.switch.
- Support: dashboard.view, organizations.switch.
- Null/unassigned role or unknown permission: deny. Demo receives only the four existing operational permissions in isolated memory, with no management/switch permission.

Migration 8 only assigns Owner on first introduction of RoleName, where an organization's sole legacy ClientUser maps through Users to that membership. Multiple historical accounts and extra cross-organization memberships are not inferred to be founders. Status/credentials and existing operational rows remain untouched. Reruns preserve all assignments (including NULL), validate exact permission policy, and fail closed on policy drift. Legacy users imported through migration 7 after RBAC exists need manual role review; signup explicitly creates an Owner membership. An organization without a verified Owner requires authorized administrative resolution, not an automatic ownership guess.

The dashboard currently exposes existing contact details and revenue KPIs to every defined role; finer data minimization is not implemented. Management only assigns roles: no invitation, membership creation/reactivation, or role-change audit history exists. Last-owner protection covers the app endpoint, not unrestricted direct SQL administration.

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
3. Insert seller, organization, scrypt-hashed legacy account, global user, and active Owner membership in one transaction.
4. Rotate into an authenticated seller session.

### Login

1. Find an active global user by username and normalized email, joined to active memberships and their organization/seller records. Prefer the legacy organization; otherwise use the first active organization ordered by seller ID.
2. Reject locked accounts; increment and persist failures up to the three-attempt lock.
3. Verify a recognized Werkzeug hash, or constant-time compare a legacy plaintext value.
4. Upgrade a successfully matched legacy value to scrypt and clear failures. Mirror exact credential/lockout values to ClientUsers in the same transaction.
5. Rotate the signed session and CSRF token. Session `id` remains the legacy account ID; `global_user_id` is distinct. Every protected request resolves memberships by legacy ID and rejects mismatched global identity, seller/organization, inactive membership, inactive user, or lockout. Old signed sessions can obtain the missing global/organization ID only through their valid database mapping. Database failures fail closed. Switching uses fresh membership rows and derives all seller/display fields server-side.

If the database operation raises and explicit demo mode is configured, only matching configured demo credentials can open a demo session. Invalid database credentials do not fall through to demo mode. Demo data is returned only when the authenticated session has `is_demo=true`.

### Public order intake

1. Validate normalized domain, lengths, and a finite decimal amount from 0.01 through 99,999,999.99.
2. Resolve the public domain through its seller-to-organization mapping, then open a transaction and lock the seller/buyer/order number ranges with SQL Server `UPDLOCK, HOLDLOCK` hints.
3. Reuse a buyer by seller plus phone, otherwise allocate a seller-relative buyer number.
4. Allocate a seller-relative order number and insert a pending order.
5. The trigger creates the initial message log; commit everything together.

### Dashboard/reporting

The dashboard query joins orders/buyers to organization, active membership, and active/unlocked global user records, filtering by seller, organization, and global user IDs. These guards are repeated in order mutation SQL to reject access revoked after the initial request check. Public domain-based ordering remains intentionally unauthenticated. Search is performed in Python over the tenant-scoped result. Delivered revenue includes only delivered orders; summaries still use order creation month.

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
- Organization- and seller-scoped reads/writes, immutable server-resolved tenant mapping, plus database-level seller/buyer consistency.
- Explicit demo opt-in with environment-defined password and no hard-coded fallback credential.
- Flask debugger disabled unless explicitly requested.

## Configuration and dependencies

Runtime Python dependencies are Flask, pyodbc, and Werkzeug. Flask/Jinja handles rendering and signed-cookie sessions. SQL Server ODBC Driver 18 is an operating-system dependency and is not installed by pip.

Important environment variables are documented in `README.md`. `SESSION_SECRET` must be stable and secret for any shared environment. `SESSION_COOKIE_SECURE=true` is required behind HTTPS. SQL-authenticated Codespaces need `DB_SERVER`, `DB_USERNAME`, and `DB_PASSWORD`; trusted authentication is mainly for Windows/local SQL Server.

## Verification status

Verified offline on 2026-10-12:

- `python -m py_compile app.py tests/test_app.py tests/test_sql_integration.py`.
- Phase 2.3 offline tests: 23 tests pass with 66 subtests. Ten SQL tests require explicit opt-in.
- Public GET pages render; protected pages redirect; missing CSRF receives HTTP 400; security headers are present.
- `python -m pip check` reported no broken requirements, and `git diff --check` passed.

Historical Phase 1.5/2.1 SQL verification on 2026-10-12:

- SQL Server 17.0 Standard Developer Edition at `localhost\MSSQLSERVER01`, using Windows Authentication, ODBC Driver 18, `DB_ENCRYPT=true`, and `DB_TRUST_SERVER_CERTIFICATE=true`.
- A read-only master query confirmed zero non-system databases and that `DukaanDesk_Test` was absent. The guarded schema was adapted in memory to create only `DukaanDesk_Test`; `CODManager` remained absent.
- The Phase 1.5 fresh setup created five user tables, `vw_PendingConfirmations`, and `trg_AutoLogCreation`. Phase 2.1 added the sixth table, `Organizations`, and `trg_Organizations_ImmutableIdentity`. Neither `3_DataTesting.sql` nor `reset.sql` was executed.
- Read-only Phase 2.1 preflight found 18 sellers/users, 28 buyers, 34 orders, 52 logs, and no existing Organizations object. The organization migration inserted 18 mappings; its immediate post-migration audit preserved every legacy table count, ID sum/maximum, and the `1958.50` order total. A second migration run inserted zero rows.
- The SQL-enabled suite passed 21 tests total: 18 offline tests plus three guarded real-database tests. New coverage verified signup mapping creation, login context, complete one-to-one backfill, trusted constraints, blocked identity remapping, mismatched organization read/write denial, and ignored client tenant input, alongside all prior MVP workflow coverage.
- Read-only migration preflight on populated synthetic data found zero invalid order states, zero cross-seller orders, and zero legacy credential values. The non-destructive `5_Migration.sql` completed successfully after in-memory database-name substitution; the tenant foreign key and all four order checks remained enabled and trusted.
- Final database audit found 22 sellers/organizations/users, 34 buyers, 42 orders, and 63 logs after the new integration run. Every original row fingerprint remained intact; all new rows were uniquely named synthetic test records. There were zero missing/duplicate organization mappings and zero cross-seller orders. No cleanup deletes ran.

Phase 2.2 SQL verification on 2026-10-12:

- Read-only preflight confirmed only the selected `DukaanDesk_Test` target: 22 legacy accounts and organizations, 34 buyers, 42 orders, 63 logs; Users and OrganizationMemberships were absent. Duplicate email and missing organization counts were zero.
- Migration imported all 22 legacy identities. Tests compared entire legacy rows (including hashes/lockout values) in memory before and after migration without exposing credential values. A rerun preserved exact user/membership rows. No system database or CODManager query/write ran in this phase.
- The final full suite passed 28 tests plus 10 subtests: 21 offline and seven SQL tests. Covered duplicate-email transactional abort, exact locked-account backfill, legacy login/session compatibility, switching, forged context rejection, inactive/revoked access, no reactivation on migration rerun, and all prior order/reporting/concurrency workflows.
- Every row present before each test run in legacy tables and existing global identity tables was preserved by full-row subset checks. New synthetic fixtures remain, including inactive users and revoked memberships; aborted inserts may leave identity-number gaps.
- Final counts: 35 sellers/organizations/legacy accounts/global users, 37 memberships (35 active and 2 revoked), 48 buyers, 60 orders, and 89 logs. Zero missing user mappings, ambiguous email groups, or disabled/untrusted identity foreign keys.

Phase 2.3 SQL verification on 2026-10-12:

- Preflight found 42 users/organizations, 45 memberships, 69 orders, and 102 logs. All 42 founder mappings had a sole legacy account; no ambiguous founders existed. The three extra memberships were not promoted. Migration added the role column/FK and two policy tables only, assigning Owner to the 42 clear founders without changing status or credential/operational data.
- First-run backfill was additionally tested with a rollback-only two-legacy-account organization; both memberships remained unassigned. The fixture and its transactional new DDL were rolled back, then the additive migration was applied to the real disposable baseline.
- Final suite: 33 passed with 72 subtests (23 offline and 10 SQL tests). SQL coverage exercises every role against protected routes and UI controls, active switching, direct unauthorized POSTs, role changes without re-login, roleless denial, current-organization role management, cross-tenant targets, last-owner protection, idempotence, and policy-drift transactional rollback. No test failures occurred.
- Full legacy/identity row preservation checks passed. Existing role assignments also survived subsequent runs. Final disposable counts: 60 sellers/organizations/legacy accounts/global users, 67 memberships, 73 buyers, 125 orders, 196 logs. Roles: 58 Owner, 2 Admin, 2 Operations, 5 unassigned. The five unassigned records include additional memberships and post-RBAC locked-account import fixtures. The role FK is trusted/enabled; no ambiguous founder groups remain in persisted test data.
- No CODManager/system database operation, seed/reset, cleanup delete, Git commit/push, or deployment occurred in this phase. Tests leave uniquely named synthetic records; rolled-back inserts may leave identity gaps.

Not verified in the current environment:

- Linux/Codespace ODBC driver installation and SQL connectivity; this verification used the local Windows instance and shared-memory `sqlcmd` transport.
- HTTPS/proxy behavior, multi-process session behavior, production WSGI serving, or deployment.
- Browser visual QA beyond template rendering.

## Continuation guidance

1. Preserve uncommitted user changes. At audit time, branding edits in all HTML pages, `checking.sql`, and a tracked `.pyc` modification predated the security work.
2. Do not run `reset.sql`, delete rows, drop databases, or execute a migration without the user's confirmation and a backup.
3. Before SQL verification, inspect the target and run read-only consistency/mapping/duplicate-email/founder checks for migrations 5–8. Only the confirmed disposable test database is authorized here. Migrations 7 and 8 run explicitly in the SQL test suite; Flask never applies migrations.
4. Keep current MVP fixes separate from the future multi-store/RBAC/subscription redesign.
5. Any real connector work needs signed webhook ingestion, idempotency keys, provider credential encryption, store-level tenant boundaries, retry/dead-letter handling, and reconciliation before it can be called reliable.
6. Update this file, `README.md`, tests, and `ROADMAP.md` whenever routes, state rules, schema, or verified runtime status changes.

## Phase 2.3 status

Status: global identities, active memberships, six organization-scoped roles, and Owner-only role assignment are implemented. Global users can switch among authorized memberships; the legacy account link and one-seller-per-organization model remain transitional constraints. There is no self-service membership creation, invitation flow, connector, lifecycle, billing, or super-admin functionality. Durable role-change audits, password-change session invalidation, recovery, email verification, abuse controls, production operations, and independent security review remain priorities.
