import os
from datetime import datetime
from functools import wraps

import pyodbc
from flask import Flask, flash, redirect, render_template, request, session, url_for


def build_connection_string() -> str:
    db_server = os.getenv("DB_SERVER", ".\\SQLEXPRESS")
    db_port = os.getenv("DB_PORT")
    db_name = os.getenv("DB_NAME", "CODManager")
    server = f"{db_server},{db_port}" if db_port else db_server
    return (
        "Driver={ODBC Driver 18 for SQL Server};"
        f"Server={server};"
        f"Database={db_name};"
        "Trusted_Connection=Yes;"
        "TrustServerCertificate=Yes;"
        "Encrypt=No;"
    )


CONNECTION_STRING = build_connection_string()

app = Flask(__name__, template_folder="public", static_folder="public", static_url_path="/static")
app.secret_key = os.getenv("SESSION_SECRET", "change-this-secret-in-production")


DEMO_USERS = {
    "waqtoro-admin": {
        "id": 1,
        "email": "waqtoro@example.com",
        "username": "waqtoro-admin",
        "password": "admin123",
        "seller_id": 1,
        "business_name": "Waqtoro Watches",
        "domain_name": "waqtoro.local",
    }
}
DEMO_FAILED_ATTEMPTS = {}

FALLBACK_ORDERS = [
    {
        "OrderID": 1,
        "SellerOrderNo": 1,
        "BuyerID": 1,
        "SellerBuyerNo": 1,
        "BuyerName": "Ahmed Khan",
        "Phone": "+923339876543",
        "DeliveryAddress": "Model Town, Lahore",
        "TotalAmount": 15000.0,
        "OrderStatus": "Pending",
        "DeliveryStatus": None,
        "ActionTaken": "Pending review",
        "OrderDate": datetime.now(),
    }
]


def get_db_connection():
    return pyodbc.connect(CONNECTION_STRING)


def normalize_domain_name(value: str) -> str:
    return str(value or "").strip().lower()


def is_account_locked(attempts: int) -> bool:
    return attempts >= 3


def build_user_session(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user.get("email"),
        "username": user["username"],
        "seller_id": user["seller_id"],
        "business_name": user["business_name"],
        "domain_name": user.get("domain_name"),
    }


def db_error_text(err: Exception) -> str:
    return str(err).lower() if err else ""


def is_missing_auth_table(err: Exception) -> bool:
    return "invalid object name 'clientusers'" in db_error_text(err)


def is_missing_signup_table(err: Exception) -> bool:
    text = db_error_text(err)
    return (
        "invalid object name 'clientusers'" in text
        or "invalid object name 'sellers'" in text
        or "invalid object name 'buyers'" in text
        or "invalid object name 'orders'" in text
    )


def is_duplicate_constraint_error(err: Exception) -> bool:
    text = db_error_text(err)
    return "2627" in text or "2601" in text or "unique" in text


def is_sql_connection_error(err: Exception) -> bool:
    text = db_error_text(err)
    return "data source name not found" in text or "[im002]" in text


def require_auth(view_fn):
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view_fn(*args, **kwargs)

    return wrapped


def login_with_database(email: str, username: str, password: str) -> dict:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT TOP 1
                CU.UserID,
                CU.Username,
                CU.PasswordHash,
                CU.FailedAttempts,
                CU.IsLocked,
                S.SellerID,
                S.Email,
                S.BusinessName,
                S.DomainName
            FROM ClientUsers CU
            INNER JOIN Sellers S ON S.SellerID = CU.SellerID
            WHERE CU.Username = ? AND S.Email = ?
            """,
            (username, email),
        )
        row = cursor.fetchone()

        if not row:
            return {"ok": False, "status": 401, "message": "Invalid username or password."}

        failed_attempts = int(row.FailedAttempts or 0)
        if bool(row.IsLocked) or failed_attempts >= 3:
            return {
                "ok": False,
                "status": 423,
                "message": "Account locked after 3 failed attempts. Contact support.",
            }

        if password != row.PasswordHash:
            updated_attempts = failed_attempts + 1
            should_lock = 1 if updated_attempts >= 3 else 0
            cursor.execute(
                """
                UPDATE ClientUsers
                SET FailedAttempts = ?,
                    IsLocked = ?,
                    LastFailedAt = GETDATE()
                WHERE UserID = ?
                """,
                (updated_attempts, should_lock, row.UserID),
            )
            conn.commit()

            if should_lock:
                return {
                    "ok": False,
                    "status": 423,
                    "message": "Account locked after 3 failed attempts. Contact support.",
                }

            return {
                "ok": False,
                "status": 401,
                "message": "Invalid username or password.",
                "attempts_left": 3 - updated_attempts,
            }

        cursor.execute(
            """
            UPDATE ClientUsers
            SET FailedAttempts = 0,
                IsLocked = 0,
                LastFailedAt = NULL
            WHERE UserID = ?
            """,
            (row.UserID,),
        )
        conn.commit()

        return {
            "ok": True,
            "user": {
                "id": int(row.UserID),
                "email": row.Email,
                "username": row.Username,
                "seller_id": int(row.SellerID),
                "business_name": row.BusinessName,
                "domain_name": row.DomainName,
            },
        }
    finally:
        conn.close()


def login_with_demo_user(email: str, username: str, password: str) -> dict:
    user = DEMO_USERS.get(username)
    if not user or str(user["email"]).lower() != str(email).lower():
        return {"ok": False, "status": 401, "message": "Invalid username or password."}

    failed_attempts = DEMO_FAILED_ATTEMPTS.get(username, 0)
    if is_account_locked(failed_attempts):
        return {
            "ok": False,
            "status": 423,
            "message": "Account locked after 3 failed attempts. Contact support.",
        }

    if user["password"] != password:
        updated_attempts = failed_attempts + 1
        DEMO_FAILED_ATTEMPTS[username] = updated_attempts

        if is_account_locked(updated_attempts):
            return {
                "ok": False,
                "status": 423,
                "message": "Account locked after 3 failed attempts. Contact support.",
            }

        return {
            "ok": False,
            "status": 401,
            "message": "Invalid username or password.",
            "attempts_left": 3 - updated_attempts,
        }

    DEMO_FAILED_ATTEMPTS[username] = 0
    return {
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "seller_id": user["seller_id"],
            "business_name": user["business_name"],
            "domain_name": user["domain_name"],
        },
    }


def signup_with_database(payload: dict) -> dict:
    conn = get_db_connection()
    conn.autocommit = False

    business_name = payload["business_name"].strip()
    whatsapp_number = payload["whatsapp_number"].strip()
    email = str(payload["email"] or "").strip().lower()
    domain_name = normalize_domain_name(payload["domain_name"])

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT TOP 1 SellerID, BusinessName, WhatsAppNumber, Email, DomainName
            FROM Sellers
            WHERE DomainName = ?
            """,
            (domain_name,),
        )
        linked_seller = cursor.fetchone()

        resolved_business_name = business_name
        resolved_email = email
        resolved_domain_name = domain_name

        if linked_seller:
            same_business = str(linked_seller.BusinessName).lower() == business_name.lower()
            same_whatsapp = str(linked_seller.WhatsAppNumber) == whatsapp_number
            same_email = str(linked_seller.Email or "").lower() == email

            if not (same_business and same_whatsapp and same_email):
                raise ValueError("DOMAIN_ALREADY_LINKED")

            seller_id = int(linked_seller.SellerID)
            resolved_business_name = linked_seller.BusinessName
            resolved_email = linked_seller.Email
            resolved_domain_name = linked_seller.DomainName
        else:
            cursor.execute(
                """
                SELECT TOP 1 SellerID, BusinessName, DomainName
                FROM Sellers
                WHERE WhatsAppNumber = ?
                """,
                (whatsapp_number,),
            )
            existing_whatsapp = cursor.fetchone()

            if existing_whatsapp:
                same_business = str(existing_whatsapp.BusinessName).lower() == business_name.lower()
                if not same_business:
                    raise ValueError("WHATSAPP_ALREADY_LINKED")
                raise ValueError("WHATSAPP_DOMAIN_REQUIRED")

            cursor.execute(
                """
                INSERT INTO Sellers (BusinessName, WhatsAppNumber, Email, DomainName)
                OUTPUT INSERTED.SellerID
                VALUES (?, ?, ?, ?)
                """,
                (business_name, whatsapp_number, email, domain_name),
            )
            inserted_seller = cursor.fetchone()
            if not inserted_seller or inserted_seller[0] is None:
                raise RuntimeError("Unable to create seller account.")
            seller_id = int(inserted_seller[0])

        cursor.execute(
            """
            INSERT INTO ClientUsers (SellerID, Username, PasswordHash)
            OUTPUT INSERTED.UserID
            VALUES (?, ?, ?)
            """,
            (seller_id, payload["username"], payload["password"]),
        )
        inserted_user = cursor.fetchone()
        if not inserted_user or inserted_user[0] is None:
            raise RuntimeError("Unable to create user account.")
        user_id = int(inserted_user[0])

        conn.commit()

        return {
            "id": user_id,
            "email": resolved_email,
            "username": payload["username"],
            "seller_id": seller_id,
            "business_name": resolved_business_name,
            "domain_name": resolved_domain_name,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def filter_dashboard_orders(orders: list, raw_search: str) -> list:
    search = str(raw_search or "").strip().lower()
    if not search:
        return orders

    cleaned_numeric = "".join(ch for ch in search if (ch.isdigit() or ch in ".-"))
    has_numeric = bool(cleaned_numeric)
    numeric_search = float(cleaned_numeric) if has_numeric else None

    filtered = []
    for order in orders:
        order_id = float(order.get("OrderID", 0) or 0)
        seller_order_no = float(order.get("SellerOrderNo", 0) or 0)
        buyer_id = float(order.get("BuyerID", 0) or 0)
        seller_buyer_no = float(order.get("SellerBuyerNo", 0) or 0)

        text_pool = [
            str(order.get("BuyerName", "")).lower(),
            str(order.get("Phone", "")).lower(),
            str(order.get("DeliveryAddress", "")).lower(),
            str(order.get("DeliveryStatus", "")).lower(),
            str(order.get("ActionTaken", "")).lower(),
            str(order.get("TotalAmount", "")).lower(),
            str(order.get("OrderDate", "")).lower(),
        ]

        if has_numeric and numeric_search is not None:
            if (
                order_id == numeric_search
                or seller_order_no == numeric_search
                or buyer_id == numeric_search
                or seller_buyer_no == numeric_search
            ):
                filtered.append(order)
                continue

        if any(search in value for value in text_pool):
            filtered.append(order)

    return filtered


def fetch_orders_for_dashboard(seller_id: int, search: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                O.OrderID,
                O.SellerOrderNo,
                B.BuyerID,
                B.SellerBuyerNo,
                S.DomainName,
                COALESCE(O.BuyerName, B.FullName) AS BuyerName,
                B.Phone,
                COALESCE(O.DeliveryAddress, B.Address) AS DeliveryAddress,
                O.TotalAmount,
                O.OrderStatus,
                O.DeliveryStatus,
                CASE
                    WHEN O.OrderStatus = 'Confirmed' THEN 'Confirmed by seller'
                    WHEN O.OrderStatus = 'Cancelled' THEN 'Not confirmed by seller'
                    ELSE 'Pending review'
                END AS ActionTaken,
                O.OrderDate
            FROM Orders O
            INNER JOIN Sellers S ON O.SellerID = S.SellerID
            INNER JOIN Buyers B ON O.BuyerID = B.BuyerID AND B.SellerID = O.SellerID
            WHERE O.SellerID = ?
            ORDER BY O.OrderDate DESC
            """,
            (seller_id,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return filter_dashboard_orders(rows, search), "database"
    except Exception:
        scoped = [row for row in FALLBACK_ORDERS if row["OrderID"] == 1 or seller_id == 1]
        return filter_dashboard_orders(scoped, search), "fallback"


def place_public_order(payload: dict) -> dict:
    conn = get_db_connection()
    conn.autocommit = False

    domain_name = normalize_domain_name(payload["domain_name"])
    buyer_name = payload["buyer_name"].strip()
    phone = payload["phone"].strip()
    address = payload["address"].strip()
    total_amount = float(payload["total_amount"])

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT TOP 1 SellerID, BusinessName
            FROM Sellers
            WHERE DomainName = ?
            """,
            (domain_name,),
        )
        seller = cursor.fetchone()
        if not seller:
            raise LookupError("SELLER_NOT_FOUND")

        seller_id = int(seller.SellerID)

        # Reuse existing buyer by WhatsApp/phone so one number maps to one BuyerID per seller.
        cursor.execute(
            """
            SELECT TOP 1 BuyerID, SellerBuyerNo
            FROM Buyers
            WHERE SellerID = ? AND Phone = ?
            """,
            (seller_id, phone),
        )
        existing_buyer = cursor.fetchone()

        if existing_buyer:
            buyer_id = int(existing_buyer.BuyerID)
            seller_buyer_no = int(existing_buyer.SellerBuyerNo)
        else:
            cursor.execute(
                """
                SELECT ISNULL(MAX(SellerBuyerNo), 0) + 1 AS NextSellerBuyerNo
                FROM Buyers
                WHERE SellerID = ?
                """,
                (seller_id,),
            )
            seller_buyer_no = int(cursor.fetchone().NextSellerBuyerNo)

            cursor.execute(
                """
                INSERT INTO Buyers (SellerID, FullName, Phone, Address, SellerBuyerNo)
                OUTPUT INSERTED.BuyerID
                VALUES (?, ?, ?, ?, ?)
                """,
                (seller_id, buyer_name, phone, address, seller_buyer_no),
            )
            inserted_buyer = cursor.fetchone()
            if not inserted_buyer or inserted_buyer[0] is None:
                raise RuntimeError("Unable to create buyer profile.")
            buyer_id = int(inserted_buyer[0])

        cursor.execute(
            """
            SELECT ISNULL(MAX(SellerOrderNo), 0) + 1 AS NextSellerOrderNo
            FROM Orders
            WHERE SellerID = ?
            """,
            (seller_id,),
        )
        seller_order_no = int(cursor.fetchone().NextSellerOrderNo)

        cursor.execute(
            """
            DECLARE @InsertedOrder TABLE (OrderID INT);

            INSERT INTO Orders (SellerID, BuyerID, SellerOrderNo, BuyerName, DeliveryAddress, TotalAmount, OrderStatus)
            OUTPUT INSERTED.OrderID INTO @InsertedOrder(OrderID)
            VALUES (?, ?, ?, ?, ?, ?, 'Pending');

            SELECT TOP 1 OrderID
            FROM @InsertedOrder;
            """,
            (seller_id, buyer_id, seller_order_no, buyer_name, address, total_amount),
        )
        inserted_order = None
        while True:
            try:
                row = cursor.fetchone()
            except pyodbc.ProgrammingError:
                row = None
            if row:
                inserted_order = row
                break
            if not cursor.nextset():
                break
        if not inserted_order or inserted_order[0] is None:
            raise RuntimeError("Unable to create order.")
        order_id = int(inserted_order[0])

        conn.commit()

        return {
            "order_id": order_id,
            "seller_order_no": seller_order_no,
            "buyer_id": buyer_id,
            "seller_buyer_no": seller_buyer_no,
            "seller_id": seller_id,
            "business_name": seller.BusinessName,
            "domain_name": domain_name,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/")
def home():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("login.html")

    email = str(request.form.get("email", "")).strip().lower()
    username = str(request.form.get("username", "")).strip()
    password = str(request.form.get("password", ""))

    if not email or not username or not password:
        flash("Email, username, and password are required.", "error")
        return render_template("login.html", email=email, username=username)

    try:
        db_login = login_with_database(email, username, password)
        if not db_login.get("ok"):
            flash(db_login.get("message", "Login failed."), "warn" if db_login.get("status") == 423 else "error")
            return render_template("login.html", email=email, username=username)

        session["user"] = build_user_session(db_login["user"])
        return redirect(url_for("dashboard"))
    except Exception as err:
        if not is_missing_auth_table(err):
            app.logger.error("Database login check failed: %s", err)

        demo_login = login_with_demo_user(email, username, password)
        if not demo_login.get("ok"):
            flash(demo_login.get("message", "Invalid username or password."), "warn" if demo_login.get("status") == 423 else "error")
            return render_template("login.html", email=email, username=username)

        session["user"] = build_user_session(demo_login["user"])
        flash("Logged in using fallback demo account.", "warn")
        return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("signup.html")

    payload = {
        "business_name": str(request.form.get("businessName", "")).strip(),
        "whatsapp_number": str(request.form.get("whatsappNumber", "")).strip(),
        "email": str(request.form.get("email", "")).strip().lower(),
        "domain_name": normalize_domain_name(request.form.get("domainName", "")),
        "username": str(request.form.get("username", "")).strip(),
        "password": str(request.form.get("password", "")),
        "confirm_password": str(request.form.get("confirmPassword", "")),
    }

    if not all(
        [
            payload["business_name"],
            payload["whatsapp_number"],
            payload["email"],
            payload["domain_name"],
            payload["username"],
            payload["password"],
            payload["confirm_password"],
        ]
    ):
        flash("Please fill all signup fields.", "error")
        return render_template("signup.html", form=payload)

    if "@" not in payload["email"] or "." not in payload["email"].split("@")[-1]:
        flash("Please provide a valid email address.", "error")
        return render_template("signup.html", form=payload)

    if not all(ch.isalnum() or ch in ".-" for ch in payload["domain_name"]):
        flash("Domain name can only contain letters, numbers, dots, and hyphens.", "error")
        return render_template("signup.html", form=payload)

    if len(payload["password"]) < 6:
        flash("Password must be at least 6 characters.", "error")
        return render_template("signup.html", form=payload)

    if payload["password"] != payload["confirm_password"]:
        flash("Passwords do not match.", "error")
        return render_template("signup.html", form=payload)

    try:
        created_user = signup_with_database(payload)
        session["user"] = build_user_session(created_user)
        flash("Signup successful.", "success")
        return redirect(url_for("dashboard"))
    except ValueError as err:
        code = str(err)
        if code == "WHATSAPP_ALREADY_LINKED":
            flash("This WhatsApp number is already linked to another business.", "warn")
        elif code == "DOMAIN_ALREADY_LINKED":
            flash("This domain is already linked to another seller.", "warn")
        elif code == "WHATSAPP_DOMAIN_REQUIRED":
            flash("This business already exists with a different domain. Use the original domain assigned to this seller.", "warn")
        else:
            flash("Signup failed.", "error")
        return render_template("signup.html", form=payload)
    except Exception as err:
        if is_duplicate_constraint_error(err):
            flash("This email or username is already registered. Please choose different credentials.", "warn")
        elif is_sql_connection_error(err):
            flash("Database connection is not configured on this machine.", "error")
        elif is_missing_signup_table(err):
            flash("Signup table is missing. Run your SQL setup scripts first.", "error")
        else:
            app.logger.error("Signup failed: %s", err)
            flash("Signup failed due to a server or database error.", "error")
        return render_template("signup.html", form=payload)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@require_auth
def dashboard():
    user = session["user"]
    search = str(request.args.get("search", "")).strip()
    orders, source = fetch_orders_for_dashboard(user["seller_id"], search)
    return render_template("dashboard.html", user=user, orders=orders, search=search, source=source)


@app.post("/orders/<int:order_id>/action")
@require_auth
def update_order_action(order_id: int):
    action = str(request.form.get("action", "")).strip().lower()
    if action not in {"confirm", "not_confirm"}:
        flash("Action must be confirm or not_confirm.", "error")
        return redirect(url_for("dashboard", search=request.form.get("search", "")))

    next_status = "Confirmed" if action == "confirm" else "Cancelled"
    next_delivery_status = "Pending" if action == "confirm" else None

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE Orders
            SET OrderStatus = ?,
                DeliveryStatus = ?
            WHERE OrderID = ?
              AND SellerID = ?
            """,
            (next_status, next_delivery_status, order_id, session["user"]["seller_id"]),
        )
        rows_affected = cursor.rowcount
        conn.commit()

        if rows_affected <= 0:
            flash("Order not found for this seller.", "warn")
        else:
            flash("Order action updated.", "success")
    except Exception as err:
        app.logger.error("Order action update failed: %s", err)
        flash("Unable to update order action right now.", "error")
    finally:
        if conn:
            conn.close()

    return redirect(url_for("dashboard", search=request.form.get("search", "")))


@app.post("/orders/<int:order_id>/status")
@require_auth
def update_order_status(order_id: int):
    status = str(request.form.get("status", "")).strip().lower()
    status_map = {
        "pending": "Pending",
        "delivered": "Delivered",
        "returned_by_buyer": "Returned by buyer",
    }
    next_delivery_status = status_map.get(status)

    if not next_delivery_status:
        flash("Status must be pending, delivered, or returned_by_buyer.", "error")
        return redirect(url_for("dashboard", search=request.form.get("search", "")))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE Orders
            SET DeliveryStatus = ?
            WHERE OrderID = ?
              AND SellerID = ?
              AND OrderStatus = 'Confirmed'
              AND DeliveryStatus = 'Pending'
            """,
            (next_delivery_status, order_id, session["user"]["seller_id"]),
        )
        rows_affected = cursor.rowcount
        conn.commit()

        if rows_affected <= 0:
            flash("Only confirmed orders with pending status can be updated.", "warn")
        else:
            flash("Delivery status updated.", "success")
    except Exception as err:
        app.logger.error("Order delivery status update failed: %s", err)
        flash("Unable to update delivery status right now.", "error")
    finally:
        if conn:
            conn.close()

    return redirect(url_for("dashboard", search=request.form.get("search", "")))


@app.route("/store", methods=["GET"])
@app.route("/store/<domain_name>", methods=["GET"])
def store(domain_name=None):
    return render_template("store.html", domain_name=normalize_domain_name(domain_name or ""))


@app.post("/store-order")
def submit_store_order():
    payload = {
        "domain_name": normalize_domain_name(request.form.get("domainName", "")),
        "buyer_name": str(request.form.get("buyerName", "")).strip(),
        "phone": str(request.form.get("phone", "")).strip(),
        "address": str(request.form.get("address", "")).strip(),
        "total_amount": request.form.get("totalAmount", "0"),
    }

    try:
        total_amount = float(payload["total_amount"])
    except (TypeError, ValueError):
        total_amount = 0

    if not payload["domain_name"] or not payload["buyer_name"] or not payload["phone"] or not payload["address"] or total_amount <= 0:
        flash("Please enter valid domain, buyer name, phone, address, and amount.", "error")
        return render_template("store.html", domain_name=payload["domain_name"], form=payload)

    payload["total_amount"] = total_amount

    try:
        result = place_public_order(payload)
        flash(
            f"Order #{result['seller_order_no']} placed for {result['business_name']}. Buyer ID: {result['seller_buyer_no']}.",
            "success",
        )
        return render_template("store.html", domain_name=payload["domain_name"])
    except LookupError:
        flash("Seller not found for this domain.", "error")
        return render_template("store.html", domain_name=payload["domain_name"], form=payload)
    except Exception as err:
        app.logger.error("Public order placement failed: %s", err)
        flash("Unable to place order right now.", "error")
        return render_template("store.html", domain_name=payload["domain_name"], form=payload)


@app.get("/login.html")
def login_html_redirect():
    return redirect(url_for("login"))


@app.get("/signup.html")
def signup_html_redirect():
    return redirect(url_for("signup"))


@app.get("/dashboard.html")
def dashboard_html_redirect():
    return redirect(url_for("dashboard"))


@app.get("/store.html")
def store_html_redirect():
    return redirect(url_for("store"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
