# DukaanDesk Roadmap

Last updated: 2026-10-12

## Product direction

DukaanDesk should evolve from the current single-domain COD operations MVP into a multi-tenant B2B SaaS for businesses that already sell through Shopify, WooCommerce, or custom websites. A business should eventually connect multiple stores, assign employees role-based access, consolidate orders and analytics, and manage a subscription. A platform super admin should manage tenant onboarding, plans, service health, and support operations.

This direction is intentionally not implemented in the current security/MVP pass. It requires explicit architecture and migration design rather than incremental columns added to the coursework schema.

## Completed in the current MVP hardening pass

- Replaced plaintext storage for new passwords with Werkzeug scrypt hashes.
- Added transparent hash upgrade after a successful login with a legacy plaintext value.
- Removed always-available hard-coded demo authentication; demo mode now requires explicit environment configuration.
- Isolated demo sessions and orders from database-backed seller sessions.
- Added CSRF protection to every POST form and endpoint.
- Added session rotation, eight-hour expiry, secure cookie options, private-page no-store behavior, request limits, and security headers.
- Added SQL-authenticated connection support and secure ODBC transport defaults.
- Prevented unauthenticated signup from attaching a new user to an existing seller.
- Enforced tenant-scoped order mutations and valid one-way order/delivery transitions.
- Added audit log rows for successful seller state changes.
- Validated field lengths, domain/username formats, and finite decimal order amounts.
- Added locking around seller-relative buyer/order number allocation.
- Corrected delivered-revenue calculations and malformed-search handling.
- Made the fresh schema refuse to overwrite an existing database.
- Made sample data idempotent and stored its password as a hash.
- Made the order trigger multi-row safe and corrected the example revenue report.
- Added a transactional, non-destructive schema hardening migration with data preflight checks.
- Added automated coverage for critical security and workflow behavior.
- Replaced the unusable README and added a complete technical handoff.

Completion here means code/tests were verified without SQL Server. It does not mean the migration or SQL-backed flows have been executed.

## P0 — required before any real launch

1. **Verify on a disposable SQL Server clone**
   - Back up existing data.
   - Run read-only preflight queries from `5_Migration.sql`.
   - Apply `5_Migration.sql` and `2_Logic.sql` only to the clone first.
   - Exercise signup, hashed and legacy login, lockout, public order creation, concurrent numbering, all valid/invalid state transitions, message logs, dashboard search, and summaries.

2. **Remove remaining legacy plaintext exposure**
   - Inventory `ClientUsers.PasswordHash` without printing credential values.
   - Build a forced password-reset flow for any row that is not a recognized hash.
   - Invalidate old sessions after password/account changes.

3. **Add account recovery and identity controls**
   - Verified email ownership, expiring single-use reset tokens, secure account unlock, and password change.
   - Rate limiting by account and IP; audit authentication events.
   - Decide whether MFA is mandatory for owners/admins.

4. **Harden public order intake**
   - Rate limiting, abuse monitoring, bot mitigation, idempotency key, and duplicate-order policy.
   - Replace buyer-entered total amount with trusted product/cart data or signed connector payloads. The current public form lets the buyer choose the amount and is only a workflow demonstration.

5. **Production runtime and secrets**
   - Use a maintained production WSGI server, HTTPS, stable `SESSION_SECRET`, `SESSION_COOKIE_SECURE=true`, least-privilege SQL credentials, and a secret manager.
   - Add health/readiness endpoints that do not leak configuration.
   - Establish structured logs, error tracking, metrics, alerting, backups, and tested restoration.
   - Add a server-side/shared session design before multi-instance scaling.

6. **Independent security review**
   - Dependency scanning, SAST, tenant-boundary tests, CSRF/session review, SQL permissions review, and penetration testing.

## P1 — finish the current operational MVP

1. Add order decision/delivery timestamps and base monthly operational reports on the relevant completion timestamp rather than `OrderDate`.
2. Add pagination and database-side search/filtering before seller order volume grows.
3. Add an owner-only buyer/order detail page and immutable audit history.
4. Add optimistic concurrency or row-version checks with clear conflict messages.
5. Normalize phone numbers and domains consistently, including international and IDN policy.
6. Add controlled account closure/data export and retention rules.
7. Add browser-level accessibility/responsive visual tests.
8. Remove the unused Node dependency tree after confirming no external workflow depends on it.
9. Replace development seed credentials with a safer first-run admin creation mechanism.

## P2 — multi-tenant SaaS foundation

Design this as a versioned migration and service-boundary project. Do not overload `Sellers.DomainName` or the current session dictionary.

1. **Tenant model**
   - Introduce `Organizations`/business tenants with immutable tenant IDs.
   - Move subscription and ownership boundaries to the organization.
   - Define tenant-aware unique keys, query guards, audit records, exports, and deletion policy.

2. **Users, memberships, and RBAC**
   - Separate global user identity from organization membership.
   - Owner-managed invitations with expiry and revocation.
   - Roles/permissions such as owner, admin, order operator, support, analyst, and read-only.
   - Store-scoped assignments where needed; deny by default and test every permission boundary.

3. **Multiple connected stores**
   - `Stores` belong to an organization and carry provider/type/status metadata.
   - Encrypted provider credentials or OAuth grants; never store raw tokens in general tables/logs.
   - Per-store settings, domain mapping, currency/timezone, import cursors, and connection health.

4. **Connector platform**
   - Shopify OAuth/webhooks, WooCommerce REST/webhooks, and a documented custom-store API.
   - Verify webhook signatures before parsing; persist raw event metadata safely.
   - Idempotent ingestion, canonical order mapping, retry/backoff, dead-letter handling, and reconciliation jobs.
   - Provider API version monitoring and disconnect/re-authorize flows.

5. **Canonical commerce model**
   - External order IDs, line items, products/variants, taxes, discounts, shipping, currency, fulfillment/payment states, customers, and store provenance.
   - Preserve provider payload references while keeping analytics queryable.

6. **Analytics**
   - Organization/store/date filters, timezone-aware metrics, COD confirmation/conversion/return rates, revenue definitions, exports, and scheduled reports.
   - Document metric semantics and exclude test/cancelled/refunded data consistently.

## P3 — platform administration and subscriptions

1. Separate platform-super-admin authentication and authorization from tenant roles; require strong MFA and comprehensive audit logs.
2. Tenant onboarding, suspension/reactivation, support impersonation with explicit consent/reason/expiry, and service health views.
3. Plans, trials, entitlements, usage metering, invoices, failed-payment handling, grace periods, and billing webhooks.
4. Feature gates enforced server-side, not only hidden in the UI.
5. Support tooling, incident history, tenant-safe diagnostics, and privacy-aware data access.
6. Compliance foundations: data processing terms, retention, deletion/export, regional hosting decisions, access reviews, and incident response.

## Deferred/non-goals for the present pass

- No Shopify, WooCommerce, or custom-store integration.
- No employee invitation or RBAC schema.
- No platform super-admin UI or API.
- No subscription/billing implementation.
- No framework rewrite, SPA conversion, microservices split, or queue introduction.
- No deployment, commit, push, or live database modification.
