import unittest
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app as dukaan


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_instance = cursor
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False
        self.autocommit = True

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


class SequenceCursor:
    def __init__(self, fetch_results=(), rowcount=1):
        self.fetch_results = list(fetch_results)
        self.rowcount = rowcount
        self.executions = []

    def execute(self, sql, params=()):
        self.executions.append((sql, params))
        return self

    def fetchone(self):
        return self.fetch_results.pop(0) if self.fetch_results else None


class DukaanDeskTests(unittest.TestCase):
    TEST_ORGANIZATION_ID = "11111111-1111-1111-1111-111111111111"

    def setUp(self):
        dukaan.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = dukaan.app.test_client()

    def csrf(self):
        self.client.get("/login")
        with self.client.session_transaction() as current_session:
            return current_session["csrf_token"]

    def sign_in_session(self, seller_id=42, is_demo=False, organization_id=None):
        token = self.csrf()
        with self.client.session_transaction() as current_session:
            current_session["user"] = {
                "id": 7,
                "email": "owner@example.com",
                "username": "owner",
                "seller_id": seller_id,
                "organization_id": organization_id or (
                    dukaan.DEMO_ORGANIZATION_ID if is_demo else self.TEST_ORGANIZATION_ID
                ),
                "business_name": "Test Shop",
                "domain_name": "test.local",
                "is_demo": is_demo,
            }
        return token

    def test_public_pages_and_auth_redirects(self):
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.get("/signup").status_code, 200)
        self.assertEqual(self.client.get("/store/test.local").status_code, 200)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        response = self.client.get("/login")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post(
            "/login",
            data={"email": "x@example.com", "username": "user", "password": "password"},
        )
        self.assertEqual(response.status_code, 400)

    def test_password_hash_and_legacy_upgrade_detection(self):
        password_hash = dukaan.generate_password_hash("correct horse battery staple")
        self.assertEqual(
            dukaan.verify_password(password_hash, "correct horse battery staple"),
            (True, False),
        )
        self.assertEqual(dukaan.verify_password("legacy-secret", "legacy-secret"), (True, True))
        self.assertEqual(dukaan.verify_password("legacy-secret", "wrong"), (False, True))

    def test_demo_login_requires_explicit_mode_and_configured_credentials(self):
        token = self.csrf()
        demo_user = {
            "id": 1,
            "email": "demo@example.com",
            "username": "demo-owner",
            "password_hash": dukaan.generate_password_hash("demo-password"),
            "seller_id": 1,
            "organization_id": dukaan.DEMO_ORGANIZATION_ID,
            "business_name": "Demo Shop",
            "domain_name": "demo.local",
        }
        with (
            patch.object(dukaan, "DEMO_MODE", True),
            patch.dict(dukaan.DEMO_USERS, {"demo-owner": demo_user}, clear=True),
            patch.object(dukaan, "login_with_database", side_effect=RuntimeError("database offline")),
        ):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "email": "demo@example.com",
                    "username": "demo-owner",
                    "password": "demo-password",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))
        with self.client.session_transaction() as current_session:
            self.assertTrue(current_session["user"]["is_demo"])

    def test_database_failure_never_exposes_demo_rows_to_normal_session(self):
        with patch.object(dukaan, "get_db_connection", side_effect=RuntimeError("database offline")):
            orders, source = dukaan.fetch_orders_for_dashboard(
                1, self.TEST_ORGANIZATION_ID, allow_demo=False
            )
        self.assertEqual(orders, [])
        self.assertEqual(source, "database unavailable")

    def test_demo_order_can_complete_the_mvp_state_flow(self):
        demo_user = {
            "id": 1,
            "email": "demo@example.com",
            "username": "demo-owner",
            "password_hash": dukaan.generate_password_hash("demo-password"),
            "seller_id": 1,
            "organization_id": dukaan.DEMO_ORGANIZATION_ID,
            "business_name": "Demo Shop",
            "domain_name": "demo.local",
        }
        demo_orders = [
            {
                "OrderID": 1,
                "SellerID": 1,
                "SellerOrderNo": 1,
                "BuyerID": 1,
                "SellerBuyerNo": 1,
                "BuyerName": "Buyer",
                "Phone": "+923001234567",
                "DeliveryAddress": "Lahore",
                "TotalAmount": Decimal("100.00"),
                "OrderStatus": "Pending",
                "DeliveryStatus": None,
                "ActionTaken": "Pending review",
                "OrderDate": datetime.now(),
            }
        ]
        with (
            patch.object(dukaan, "DEMO_MODE", True),
            patch.dict(dukaan.DEMO_USERS, {"demo-owner": demo_user}, clear=True),
            patch.object(dukaan, "DEMO_ORDERS", demo_orders),
        ):
            token = self.sign_in_session(seller_id=1, is_demo=True)
            self.assertEqual(self.client.get("/dashboard").status_code, 200)
            self.client.post(
                "/orders/1/action",
                data={"csrf_token": token, "action": "confirm", "search": ""},
            )
            self.assertEqual(demo_orders[0]["OrderStatus"], "Confirmed")
            self.client.post(
                "/orders/1/status",
                data={"csrf_token": token, "status": "delivered", "search": ""},
            )
            self.assertEqual(demo_orders[0]["DeliveryStatus"], "Delivered")
            summary = self.client.get("/summary")
            self.assertEqual(summary.status_code, 200)
            self.assertIn(b"Rs. 100.00", summary.data)

    def test_signup_stores_a_hash(self):
        cursor = SequenceCursor(
            [None, None, (11,), (self.TEST_ORGANIZATION_ID,), (22,)]
        )
        connection = FakeConnection(cursor)
        payload = {
            "business_name": "Acme",
            "whatsapp_number": "+923001234567",
            "email": "owner@acme.test",
            "domain_name": "acme.test",
            "username": "acme-owner",
            "password": "a-long-password",
        }
        with patch.object(dukaan, "get_db_connection", return_value=connection):
            created = dukaan.signup_with_database(payload)

        password_insert = next(item for item in cursor.executions if "INSERT INTO ClientUsers" in item[0])
        stored_value = password_insert[1][2]
        self.assertTrue(dukaan.check_password_hash(stored_value, payload["password"]))
        self.assertNotEqual(stored_value, payload["password"])
        self.assertEqual(created["seller_id"], 11)
        self.assertEqual(created["organization_id"], self.TEST_ORGANIZATION_ID)
        organization_insert = next(
            item for item in cursor.executions if "INSERT INTO Organizations" in item[0]
        )
        self.assertEqual(organization_insert[1], (11, "Acme"))
        self.assertEqual(connection.commit_count, 1)
        self.assertTrue(connection.closed)

    def test_existing_domain_cannot_create_an_unauthorized_user(self):
        existing_seller = SimpleNamespace(
            SellerID=5,
            BusinessName="Existing",
            WhatsAppNumber="+923001234567",
            Email="owner@example.com",
            DomainName="existing.test",
        )
        cursor = SequenceCursor([existing_seller])
        connection = FakeConnection(cursor)
        payload = {
            "business_name": "Existing",
            "whatsapp_number": "+923001234567",
            "email": "owner@example.com",
            "domain_name": "existing.test",
            "username": "attacker",
            "password": "a-long-password",
        }
        with patch.object(dukaan, "get_db_connection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "DOMAIN_ALREADY_LINKED"):
                dukaan.signup_with_database(payload)
        self.assertEqual(connection.rollback_count, 1)

    def test_legacy_database_password_is_upgraded_after_login(self):
        row = SimpleNamespace(
            UserID=3,
            Username="owner",
            PasswordHash="legacy-secret",
            FailedAttempts=0,
            IsLocked=False,
            SellerID=8,
            Email="owner@example.com",
            BusinessName="Shop",
            DomainName="shop.test",
            OrganizationID=self.TEST_ORGANIZATION_ID,
        )
        cursor = SequenceCursor([row])
        connection = FakeConnection(cursor)
        with patch.object(dukaan, "get_db_connection", return_value=connection):
            result = dukaan.login_with_database("owner@example.com", "owner", "legacy-secret")

        self.assertTrue(result["ok"])
        self.assertEqual(result["user"]["organization_id"], self.TEST_ORGANIZATION_ID)
        upgrade = next(item for item in cursor.executions if "SET PasswordHash" in item[0])
        self.assertTrue(dukaan.check_password_hash(upgrade[1][0], "legacy-secret"))
        self.assertEqual(connection.commit_count, 1)

    def test_malformed_numeric_search_does_not_crash(self):
        orders = [{"OrderID": 1, "BuyerName": "Example", "TotalAmount": 12}]
        self.assertEqual(dukaan.filter_dashboard_orders(orders, "1.2.3"), [])
        self.assertEqual(dukaan.filter_dashboard_orders(orders, "example"), orders)

    def test_common_sql_connection_states_are_recognized(self):
        self.assertTrue(dukaan.is_sql_connection_error(Exception("08001 connection failed")))
        self.assertTrue(dukaan.is_sql_connection_error(Exception("[IM002] missing driver")))
        self.assertFalse(dukaan.is_sql_connection_error(Exception("2627 duplicate key")))

    def test_nan_and_infinite_order_amounts_are_rejected(self):
        token = self.csrf()
        for invalid_value in ("nan", "inf", "-1", "0", "0.001"):
            with self.subTest(value=invalid_value), patch.object(dukaan, "place_public_order") as place:
                response = self.client.post(
                    "/store-order",
                    data={
                        "csrf_token": token,
                        "domainName": "shop.test",
                        "buyerName": "Buyer",
                        "phone": "+923001234567",
                        "address": "Lahore",
                        "totalAmount": invalid_value,
                    },
                )
                self.assertEqual(response.status_code, 200)
                place.assert_not_called()

    def test_order_action_is_seller_scoped_and_one_way(self):
        token = self.sign_in_session(seller_id=42)
        cursor = SequenceCursor(rowcount=1)
        connection = FakeConnection(cursor)
        with patch.object(dukaan, "get_db_connection", return_value=connection):
            response = self.client.post(
                "/orders/9/action",
                data={
                    "csrf_token": token,
                    "action": "confirm",
                    "search": "",
                    "organization_id": "22222222-2222-2222-2222-222222222222",
                },
            )

        self.assertEqual(response.status_code, 302)
        update = next(item for item in cursor.executions if "UPDATE Orders" in item[0])
        self.assertIn("SellerID = ?", update[0])
        self.assertIn("Org.OrganizationID = ?", update[0])
        self.assertIn("OrderStatus = 'Pending'", update[0])
        self.assertEqual(update[1][-3:], (9, 42, self.TEST_ORGANIZATION_ID))
        self.assertEqual(connection.commit_count, 1)

    def test_legacy_session_resolves_organization_from_user_mapping(self):
        row = SimpleNamespace(
            UserID=7,
            SellerID=42,
            OrganizationID=self.TEST_ORGANIZATION_ID,
        )
        connection = FakeConnection(SequenceCursor([row]))
        with dukaan.app.test_request_context("/dashboard"):
            dukaan.session["user"] = {
                "id": 7,
                "seller_id": 42,
                "username": "owner",
                "business_name": "Test Shop",
                "is_demo": False,
            }
            with patch.object(dukaan, "get_db_connection", return_value=connection):
                self.assertTrue(dukaan.resolve_legacy_organization_context())
            self.assertEqual(
                dukaan.session["user"]["organization_id"], self.TEST_ORGANIZATION_ID
            )
        query = connection.cursor_instance.executions[0]
        self.assertIn("WHERE CU.UserID = ?", query[0])
        self.assertEqual(query[1], (7,))
        self.assertTrue(connection.closed)

    def test_organization_migration_is_additive_and_backfills_sellers(self):
        migration = (Path(__file__).parents[1] / "6_Organizations.sql").read_text(
            encoding="utf-8"
        )
        normalized = migration.upper()
        self.assertIn("WHERE NOT EXISTS", normalized)
        self.assertIn("LEGACYSELLERID", normalized)
        self.assertIn("TRG_ORGANIZATIONS_IMMUTABLEIDENTITY", normalized)
        self.assertNotIn("DROP TABLE", normalized)
        self.assertNotIn("DELETE FROM", normalized)
        self.assertNotIn("TRUNCATE", normalized)

    def test_delivery_transition_rejects_pending_as_an_outcome(self):
        token = self.sign_in_session()
        with patch.object(dukaan, "get_db_connection") as connection:
            response = self.client.post(
                "/orders/9/status",
                data={"csrf_token": token, "status": "pending", "search": ""},
            )
        self.assertEqual(response.status_code, 302)
        connection.assert_not_called()

    def test_kpis_only_count_delivered_revenue(self):
        orders = [
            {"TotalAmount": Decimal("100.00"), "OrderStatus": "Confirmed", "DeliveryStatus": "Delivered"},
            {"TotalAmount": Decimal("50.00"), "OrderStatus": "Cancelled", "DeliveryStatus": None},
            {"TotalAmount": Decimal("25.00"), "OrderStatus": "Confirmed", "DeliveryStatus": "Returned by buyer"},
        ]
        kpis = dukaan.build_dashboard_kpis(orders, [])
        self.assertEqual(kpis["revenue"], 100.0)
        self.assertEqual(kpis["cancelled_or_returned"], 2)

    def test_summary_groups_recent_outcomes(self):
        orders = [
            {
                "OrderID": 1,
                "OrderDate": datetime.now(),
                "OrderStatus": "Confirmed",
                "DeliveryStatus": "Delivered",
            }
        ]
        sections = dukaan.build_summary_sections(orders)
        delivered = next(section for section in sections if section["key"] == "delivered")
        self.assertEqual(delivered["total"], 1)


if __name__ == "__main__":
    unittest.main()
