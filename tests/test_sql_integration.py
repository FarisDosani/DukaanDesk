import os
import unittest
import uuid
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

    @classmethod
    def tearDownClass(cls):
        cls.connection.close()

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
        self.assertEqual(mismatched_dashboard.status_code, 200)
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
        with owner_client.session_transaction() as current_session:
            session_user = dict(current_session["user"])
            session_user["organization_id"] = organization_id
            current_session["user"] = session_user

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
