# DukaanDesk Roadmap

Last updated: 2026-10-12

## Product direction

DukaanDesk should evolve from the current single-domain COD operations MVP into a multi-tenant B2B SaaS for businesses that already sell through Shopify, WooCommerce, or custom websites. A business should eventually connect multiple stores, assign employees role-based access, consolidate orders and analytics, and manage a subscription. A platform super admin should manage tenant onboarding, plans, service health, and support operations.

Phase 2.1 added organization IDs; Phase 2.2 added global users, memberships, and switching; Phase 2.3 adds six organization-scoped roles, explicit SQL permissions, and Owner-only role assignment. Multi-store, invitations, super-admin, and subscriptions remain unimplemented.

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
- Added `Organizations` as immutable tenant identities with a unique legacy `SellerID` mapping.
- Added an idempotent transactional migration that safely backfills every existing seller.
- Resolved tenant context from authenticated database mappings and enforced organization plus seller scope on protected order reads/writes.
- Added global Users with unique normalized email/username, preserved legacy credential/lockout copies, and active/inactive/revoked organization memberships.
- Added migration 7 with transactional backfill, duplicate-email ambiguity rejection, idempotence, and no membership reactivation on rerun.
- Revalidate memberships and user activity/lockout on every protected request and in protected order SQL; provide a minimal CSRF-protected organization selector.
- Phase 2.3: SQL role assignments and explicit grants, conservative founder backfill, deny-by-default route/query guards, role-aware navigation, roster access, and Owner-only role assignment with last-owner protection.

The original hardening and Phase 2.1/2.2 work have been verified against the disposable SQL Server database described below. This does not establish production readiness.

## Verification checkpoint — 2026-10-12

- Offline verification: 23 tests pass with 66 subtests; ten guarded SQL tests require explicit opt-in.
- SQL verification: the full suite reports 33 passed and 72 subtests against confirmed disposable `DukaanDesk_Test` on `localhost\MSSQLSERVER01`. No test failures occurred.
- Signup, password hashing, hashed login, legacy-plaintext upgrade, lockout, order creation, confirmation/cancellation, delivery, tenant isolation, exact message logs, summaries, and concurrent seller-relative numbering were exercised against real SQL Server.
- Read-only migration preflight found no invalid or cross-seller rows. The organization migration backfilled all 18 existing sellers without changing legacy row fingerprints, and a second run inserted zero rows. Seed and reset scripts were not run; `CODManager` remained absent.
- **Phase 2.1 organization foundation is complete.** The additive migration preserved the original synthetic dataset, backfilled every seller, and passed idempotence, immutability, mapping, and cross-organization tests.
- **Phase 2.2 global users/memberships are complete within scope.** Migration imported all 22 initial accounts without ambiguous emails; full original row comparisons passed. SQL tests verify exact locked-account backfill, ambiguity rollback, switching, legacy-session upgrade, inactive/revoked access denial, and rerun preservation. No membership provisioning, invitations, or roles were added.
- **Phase 2.3 RBAC is complete within scope.** Migration assigned 42 verified sole-account founders as Owner, leaving three additional memberships unassigned. All six roles, direct unauthorized actions, role changes, roleless denial, tenant isolation, last-owner protection, policy drift rejection, and idempotence passed. Pre-existing data was preserved. Durable role-change audits and owner recovery remain required before broader administration/launch.

## P0 — required before any real launch

1. **Verify on a disposable SQL Server clone — completed 2026-10-12**
   - Created only the previously absent `DukaanDesk_Test`; no existing database was overwritten.
   - Installed the fresh schema/view/trigger, ran read-only migration preflight, and applied both non-destructive migrations successfully.
   - Verified signup, hashed login, legacy-password upgrade, lockout, public order creation, concurrent numbering, valid/rejected state transitions, tenant isolation, message logs, dashboard behavior, and summaries.

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

Continue this as a versioned migration and service-boundary project. Keep `Sellers.DomainName` as a legacy field and keep only the minimal authenticated organization context in the signed session.

1. **Tenant model**
   - Completed in Phase 2.1: introduce `Organizations`/business tenants with immutable tenant IDs and one-to-one legacy seller mapping.
   - Completed in Phase 2.1: require both organization and legacy seller boundaries on current protected order reads/writes.
   - Move subscription and ownership boundaries to the organization.
   - Define tenant-aware unique keys, query guards, audit records, exports, and deletion policy.

2. **Users, memberships, and RBAC**
   - Completed in Phase 2.2: global Users and OrganizationMemberships, active membership checks, server-authorized organization switching, and legacy login compatibility.
   - Completed in Phase 2.3: Owner/Admin/Operations/Finance/Marketing/Support assignments, explicit SQL grants, immediate request-time role revalidation, roster viewing, Owner-only role changes, and last-owner protection.
   - Next: durable role-change audit records, finer field-level privacy, and verified owner recovery before employee invitations/membership administration. Every current dashboard viewer sees existing contact data and KPIs.
   - Remove the mandatory legacy account dependency only through a separately designed migration; do not merge accounts automatically by email.
   - Owner-managed invitations with expiry and revocation.
   - Review the six-role permission matrix with product requirements before expanding capabilities; custom roles are not supported.
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
- No employee invitation or self-service membership creation.
- No platform super-admin UI or API.
- No subscription/billing implementation.
- No framework rewrite, SPA conversion, microservices split, or queue introduction.
- No deployment, commit, push, or live database modification.
