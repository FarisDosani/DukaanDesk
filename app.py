import hashlib
import hmac
import os
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlsplit
from copy import deepcopy
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from uuid import UUID

import pyodbc
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def odbc_value(value: str) -> str:
    """Wrap an ODBC value so semicolons and braces cannot alter the DSN."""
    return "{" + str(value).replace("}", "}}") + "}"


def build_connection_string() -> str:
    db_server = os.getenv("DB_SERVER", ".\\SQLEXPRESS")
    db_port = os.getenv("DB_PORT")
    db_name = os.getenv("DB_NAME", "CODManager")
    db_driver = os.getenv("DB_DRIVER", "ODBC Driver 18 for SQL Server")
    db_username = os.getenv("DB_USERNAME")
    db_password = os.getenv("DB_PASSWORD")
    server = f"{db_server},{db_port}" if db_port else db_server
    parts = [
        f"Driver={odbc_value(db_driver)}",
        f"Server={odbc_value(server)}",
        f"Database={odbc_value(db_name)}",
    ]

    if db_username and db_password:
        parts.extend([f"UID={odbc_value(db_username)}", f"PWD={odbc_value(db_password)}"])
    else:
        parts.append("Trusted_Connection=Yes")

    parts.extend(
        [
            f"Encrypt={'Yes' if env_flag('DB_ENCRYPT', True) else 'No'}",
            f"TrustServerCertificate={'Yes' if env_flag('DB_TRUST_SERVER_CERTIFICATE', False) else 'No'}",
            f"Connection Timeout={env_int('DB_CONNECTION_TIMEOUT', 5, 1, 60)}",
        ]
    )
    return ";".join(parts) + ";"


CONNECTION_STRING = build_connection_string()

app = Flask(__name__, template_folder="public", static_folder="public", static_url_path="/static")
configured_session_secret = os.getenv("SESSION_SECRET")
app.secret_key = configured_session_secret or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", False),
)
if not configured_session_secret:
    app.logger.warning("SESSION_SECRET is not set; sessions will be invalidated when the process restarts.")


DEMO_MODE = env_flag("DEMO_MODE", False)
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD")
DEMO_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"
DEMO_USERS = {}
if DEMO_MODE and DEMO_PASSWORD:
    demo_username = os.getenv("DEMO_USERNAME", "waqtoro-admin")
    DEMO_USERS[demo_username] = {
        "id": 1,
        "email": os.getenv("DEMO_EMAIL", "waqtoro@example.com").strip().lower(),
        "username": demo_username,
        "password_hash": generate_password_hash(DEMO_PASSWORD),
        "seller_id": 1,
        "organization_id": DEMO_ORGANIZATION_ID,
        "business_name": os.getenv("DEMO_BUSINESS_NAME", "Waqtoro Watches"),
        "domain_name": os.getenv("DEMO_DOMAIN", "waqtoro.local").strip().lower(),
    }
elif DEMO_MODE:
    app.logger.warning("DEMO_MODE is enabled but DEMO_PASSWORD is missing; demo login is disabled.")
DEMO_FAILED_ATTEMPTS = {}

DEMO_ORDERS = [
    {
        "OrderID": 1,
        "SellerID": 1,
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
    return pyodbc.connect(
        CONNECTION_STRING,
        timeout=env_int("DB_CONNECTION_TIMEOUT", 5, 1, 60),
    )


def normalize_domain_name(value: str) -> str:
    return str(value or "").strip().lower()


DOMAIN_RE = re.compile(
    r"^(?=.{1,120}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,100}$")


def validate_signup_payload(payload: dict) -> str | None:
    required = (
        "business_name",
        "whatsapp_number",
        "email",
        "domain_name",
        "username",
        "password",
        "confirm_password",
    )
    if not all(payload.get(field) for field in required):
        return "Please fill all signup fields."
    if len(payload["business_name"]) > 100:
        return "Business name must be 100 characters or fewer."
    if len(payload["whatsapp_number"]) > 20:
        return "WhatsApp number must be 20 characters or fewer."
    if len(payload["email"]) > 255 or "@" not in payload["email"] or "." not in payload["email"].split("@")[-1]:
        return "Please provide a valid email address."
    if not DOMAIN_RE.fullmatch(payload["domain_name"]):
        return "Enter a valid domain using letters, numbers, dots, and hyphens."
    if not USERNAME_RE.fullmatch(payload["username"]):
        return "Username must be 3-100 characters using letters, numbers, dots, underscores, or hyphens."
    if len(payload["password"]) < 10:
        return "Password must be at least 10 characters."
    if len(payload["password"]) > 128:
        return "Password must be 128 characters or fewer."
    if payload["password"] != payload["confirm_password"]:
        return "Passwords do not match."
    return None


def parse_order_amount(value) -> Decimal | None:
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not amount.is_finite() or amount < Decimal("0.01") or amount > Decimal("99999999.99"):
        return None
    return amount.quantize(Decimal("0.01"))


def validate_order_payload(payload: dict) -> str | None:
    if not DOMAIN_RE.fullmatch(payload["domain_name"]):
        return "Please enter a valid seller domain."
    if not payload["buyer_name"] or len(payload["buyer_name"]) > 100:
        return "Buyer name is required and must be 100 characters or fewer."
    if not payload["phone"] or len(payload["phone"]) > 20:
        return "Phone is required and must be 20 characters or fewer."
    if not payload["address"] or len(payload["address"]) > 255:
        return "Address is required and must be 255 characters or fewer."
    if payload.get("total_amount") is None:
        return "Order amount must be between 0.01 and 99,999,999.99."
    return None


def is_account_locked(attempts: int) -> bool:
    return attempts >= 3


def build_user_session(user: dict) -> dict:
    return {
        "id": user["id"],
        "global_user_id": user.get("global_user_id"),
        "email": user.get("email"),
        "username": user["username"],
        "seller_id": user["seller_id"],
        "organization_id": user.get("organization_id"),
        "business_name": user["business_name"],
        "domain_name": user.get("domain_name"),
        "is_demo": bool(user.get("is_demo", False)),
    }


def password_is_hashed(value: str) -> bool:
    return str(value or "").startswith(("scrypt:", "pbkdf2:"))


def verify_password(stored_value: str, candidate: str) -> tuple[bool, bool]:
    """Return (matches, needs_upgrade) for current hashes and legacy plaintext."""
    stored_value = str(stored_value or "")
    if password_is_hashed(stored_value):
        try:
            return check_password_hash(stored_value, candidate), False
        except (TypeError, ValueError):
            return False, False
    return hmac.compare_digest(stored_value, candidate), True


def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token, "demo_mode": DEMO_MODE and bool(DEMO_USERS), "can": has_permission}


@app.before_request
def protect_post_requests():
    if request.method != "POST":
        return None
    expected = str(session.get("csrf_token", ""))
    supplied = str(request.form.get("csrf_token", ""))
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Invalid or missing CSRF token.")
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if session.get("user") or request.path.startswith('/invitations'):
        response.headers.setdefault("Cache-Control", "no-store")
    if request.path.startswith('/invitations'):
        response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def db_error_text(err: Exception) -> str:
    return str(err).lower() if err else ""


def is_missing_auth_table(err: Exception) -> bool:
    text = db_error_text(err)
    return (
        "invalid object name 'clientusers'" in text
        or "invalid object name 'users'" in text
        or "invalid object name 'organizationmemberships'" in text
        or "invalid object name 'organizations'" in text
    )


def is_missing_signup_table(err: Exception) -> bool:
    text = db_error_text(err)
    return (
        "invalid object name 'clientusers'" in text
        or "invalid object name 'users'" in text
        or "invalid object name 'organizationmemberships'" in text
        or "invalid object name 'sellers'" in text
        or "invalid object name 'organizations'" in text
        or "invalid object name 'buyers'" in text
        or "invalid object name 'orders'" in text
    )


def is_duplicate_constraint_error(err: Exception) -> bool:
    text = db_error_text(err)
    return "2627" in text or "2601" in text or "unique" in text


def is_sql_connection_error(err: Exception) -> bool:
    text = db_error_text(err)
    markers = (
        "data source name not found",
        "[im002]",
        "08001",
        "08000",
        "08s01",
        "hyt00",
        "hyt01",
        "login timeout",
    )
    return any(marker in text for marker in markers)


def require_auth(view_fn):
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        if session["user"].get("is_demo") and not (DEMO_MODE and DEMO_USERS):
            session.clear()
            return redirect(url_for("login"))
        if not resolve_legacy_organization_context():
            session.clear()
            flash("Your account or organization access has changed. Please sign in again.", "error")
            return redirect(url_for("login"))
        return view_fn(*args, **kwargs)

    return wrapped


def has_permission(permission: str) -> bool:
    return permission in getattr(g, "permissions", frozenset())


def require_permission(permission: str):
    def decorate(view_fn):
        @require_auth
        @wraps(view_fn)
        def guarded(*args, **kwargs):
            if not has_permission(permission):
                abort(403, description="Your organization role does not permit this action.")
            return view_fn(*args, **kwargs)
        return guarded
    return decorate


def resolve_legacy_organization_context() -> bool:
    """Revalidate membership on every request; upgrade old signed sessions safely."""
    user = session.get("user")
    if not user:
        return False
    if user.get("is_demo"):
        g.permissions = frozenset({"dashboard.view", "summary.view", "orders.decide", "orders.delivery"})
        user["organization_id"] = DEMO_ORGANIZATION_ID
        session["user"] = user
        return True

    conn = None
    try:
        conn = get_db_connection()
        rows = conn.cursor().execute(
            """
            SELECT U.UserID AS GlobalUserID, U.LegacyClientUserID AS UserID,
                   U.Email, U.Username, S.SellerID, S.BusinessName, S.DomainName,
                   Org.OrganizationID, M.RoleName
            FROM Users U
            JOIN OrganizationMemberships M ON M.UserID = U.UserID AND M.Status = 'Active'
            JOIN Organizations Org ON Org.OrganizationID = M.OrganizationID
            JOIN Sellers S ON S.SellerID = Org.LegacySellerID
            WHERE ((? IS NOT NULL AND U.UserID = ?) OR
                   (? IS NULL AND U.LegacyClientUserID = ?)) AND U.IsActive = 1
              AND U.IsLocked = 0 AND U.FailedAttempts < 3
            ORDER BY S.SellerID
            """,
            (user.get("global_user_id"), user.get("global_user_id"),
             user.get("global_user_id"), user.get("id")),
        ).fetchall()
        memberships = [user_from_membership(row) for row in rows]
        g.organization_memberships = memberships
        expected_org = user.get("organization_id")
        selected = next((item for item in memberships
                         if item["seller_id"] == user.get("seller_id")
                         and (not expected_org or item["organization_id"].lower() == str(expected_org).lower())), None)
        if not selected:
            return False
        if user.get("global_user_id") is not None and user["global_user_id"] != selected["global_user_id"]:
            return False
        if user.get("id") != selected["id"]:
            return False
        # Never cache authority in the signed cookie: roles/grants are read each request.
        g.permissions = frozenset(row[0] for row in conn.cursor().execute(
            "SELECT Permission FROM RolePermissions WHERE RoleName = ?",
            (selected["role_name"],),
        ).fetchall())
        session["user"] = build_user_session(selected)
        g.role_name = selected["role_name"]
        return True
    except Exception as err:
        app.logger.error("Organization context resolution failed: %s", err)
        return False
    finally:
        if conn:
            conn.close()


def user_from_membership(row) -> dict:
    return {
        "id": int(row.UserID) if row.UserID is not None else None, "global_user_id": int(row.GlobalUserID),
        "email": row.Email, "username": row.Username,
        "seller_id": int(row.SellerID), "organization_id": str(row.OrganizationID),
        "business_name": row.BusinessName, "domain_name": row.DomainName,
        "role_name": row.RoleName,
    }


def mirror_legacy_auth(cursor, global_user_id: int):
    """Keep legacy readers compatible; Users is the authentication authority."""
    cursor.execute(
        """UPDATE CU SET PasswordHash = U.PasswordHash, FailedAttempts = U.FailedAttempts,
               IsLocked = U.IsLocked, LastFailedAt = U.LastFailedAt
           FROM ClientUsers CU JOIN Users U ON U.LegacyClientUserID = CU.UserID
           WHERE U.UserID = ?""", (global_user_id,),
    )


def login_with_database(email: str, username: str, password: str) -> dict:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT TOP 1
                U.LegacyClientUserID AS UserID,
                U.UserID AS GlobalUserID,
                U.Username,
                U.PasswordHash,
                U.FailedAttempts,
                U.IsLocked,
                S.SellerID,
                U.Email,
                S.BusinessName,
                S.DomainName,
                Org.OrganizationID, M.RoleName
            FROM Users U WITH (UPDLOCK, HOLDLOCK)
            LEFT JOIN ClientUsers CU ON CU.UserID = U.LegacyClientUserID
            JOIN OrganizationMemberships M ON M.UserID = U.UserID AND M.Status = 'Active'
            JOIN Organizations Org ON Org.OrganizationID = M.OrganizationID
            JOIN Sellers S ON S.SellerID = Org.LegacySellerID
            WHERE U.Username = ? AND U.NormalizedEmail = ? AND U.IsActive = 1
            ORDER BY CASE WHEN S.SellerID = CU.SellerID THEN 0 ELSE 1 END, S.SellerID
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

        password_matches, needs_upgrade = verify_password(row.PasswordHash, password)
        if not password_matches:
            updated_attempts = failed_attempts + 1
            should_lock = 1 if updated_attempts >= 3 else 0
            cursor.execute(
                """UPDATE Users SET FailedAttempts = ?, IsLocked = ?, LastFailedAt = GETDATE()
                   WHERE UserID = ?""",
                (updated_attempts, should_lock, row.GlobalUserID),
            )
            mirror_legacy_auth(cursor, row.GlobalUserID)
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

        if needs_upgrade:
            upgraded_hash = generate_password_hash(password)
            cursor.execute(
                """UPDATE Users SET PasswordHash = ?, FailedAttempts = 0,
                   IsLocked = 0, LastFailedAt = NULL WHERE UserID = ?""",
                (upgraded_hash, row.GlobalUserID),
            )
        else:
            cursor.execute(
                """UPDATE Users SET FailedAttempts = 0, IsLocked = 0,
                   LastFailedAt = NULL WHERE UserID = ?""", (row.GlobalUserID,),
            )
        mirror_legacy_auth(cursor, row.GlobalUserID)
        conn.commit()

        return {
            "ok": True,
            "user": user_from_membership(row),
        }
    except Exception:
        conn.rollback()
        raise
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

    if not check_password_hash(user["password_hash"], password):
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
            "organization_id": user.get("organization_id", DEMO_ORGANIZATION_ID),
            "business_name": user["business_name"],
            "domain_name": user["domain_name"],
            "is_demo": True,
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

        if linked_seller:
            raise ValueError("DOMAIN_ALREADY_LINKED")

        cursor.execute(
            """
            SELECT TOP 1 SellerID
            FROM Sellers
            WHERE WhatsAppNumber = ?
            """,
            (whatsapp_number,),
        )
        if cursor.fetchone():
            raise ValueError("WHATSAPP_ALREADY_LINKED")

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
            INSERT INTO Organizations (LegacySellerID, OrganizationName)
            OUTPUT INSERTED.OrganizationID
            VALUES (?, ?)
            """,
            (seller_id, business_name),
        )
        inserted_organization = cursor.fetchone()
        if not inserted_organization or inserted_organization[0] is None:
            raise RuntimeError("Unable to create organization.")
        organization_id = str(inserted_organization[0])

        cursor.execute(
            """
            INSERT INTO ClientUsers (SellerID, Username, PasswordHash)
            OUTPUT INSERTED.UserID
            VALUES (?, ?, ?)
            """,
            (seller_id, payload["username"], generate_password_hash(payload["password"])),
        )
        inserted_user = cursor.fetchone()
        if not inserted_user or inserted_user[0] is None:
            raise RuntimeError("Unable to create user account.")
        user_id = int(inserted_user[0])

        cursor.execute(
            """INSERT INTO Users (LegacyClientUserID, Email, Username, PasswordHash)
               OUTPUT INSERTED.UserID
               SELECT UserID, ?, Username, PasswordHash FROM ClientUsers WHERE UserID = ?""",
            (email, user_id),
        )
        global_user_id = int(cursor.fetchone()[0])
        cursor.execute(
            """INSERT INTO OrganizationMemberships (UserID, OrganizationID, Status, RoleName)
               VALUES (?, ?, 'Active', 'Owner')""", (global_user_id, organization_id),
        )

        conn.commit()

        return {
            "id": user_id,
            "global_user_id": global_user_id,
            "email": email,
            "username": payload["username"],
            "seller_id": seller_id,
            "organization_id": organization_id,
            "business_name": business_name,
            "domain_name": domain_name,
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
    try:
        numeric_search = float(cleaned_numeric) if has_numeric else None
    except ValueError:
        numeric_search = None

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


def fetch_orders_for_dashboard(
    seller_id: int,
    organization_id: str | None = None,
    search: str = "",
    apply_search: bool = True,
    allow_demo: bool = False,
    global_user_id: int | None = None,
    required_permission: str = "dashboard.view",
):
    if allow_demo and DEMO_MODE and DEMO_USERS:
        if organization_id != DEMO_ORGANIZATION_ID:
            return [], "organization unavailable"
        rows = [deepcopy(row) for row in DEMO_ORDERS if row["SellerID"] == seller_id]
        if apply_search:
            rows = filter_dashboard_orders(rows, search)
        return rows, "demo"

    if not organization_id or global_user_id is None:
        return [], "organization unavailable"

    conn = None
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
            INNER JOIN Organizations Org ON Org.LegacySellerID = O.SellerID
            INNER JOIN OrganizationMemberships M ON M.OrganizationID = Org.OrganizationID
            INNER JOIN Users U ON U.UserID = M.UserID
            INNER JOIN Buyers B ON O.BuyerID = B.BuyerID AND B.SellerID = O.SellerID
            WHERE O.SellerID = ? AND Org.OrganizationID = ?
              AND M.UserID = ? AND M.Status = 'Active' AND U.IsActive = 1
              AND U.IsLocked = 0 AND U.FailedAttempts < 3
              AND EXISTS (SELECT 1 FROM RolePermissions RP
                          WHERE RP.RoleName = M.RoleName AND RP.Permission = ?)
            ORDER BY O.OrderDate DESC
            """,
            (seller_id, organization_id, global_user_id, required_permission),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        if apply_search:
            rows = filter_dashboard_orders(rows, search)
        return rows, "database"
    except Exception as err:
        app.logger.error("Dashboard order query failed: %s", err)
        return [], "database unavailable"
    finally:
        if conn:
            conn.close()


def is_active_dashboard_order(order: dict) -> bool:
    order_status = str(order.get("OrderStatus", "") or "").strip().lower()
    delivery_status = str(order.get("DeliveryStatus", "") or "").strip().lower()

    if order_status == "pending":
        return True

    return order_status == "confirmed" and (not delivery_status or delivery_status == "pending")


def get_last_12_months_desc() -> list:
    now = datetime.now()
    year = now.year
    month = now.month
    months = []

    for _ in range(12):
        month_start = datetime(year, month, 1)
        months.append(
            {
                "key": f"{year:04d}-{month:02d}",
                "label": month_start.strftime("%b %Y"),
            }
        )

        month -= 1
        if month == 0:
            month = 12
            year -= 1

    return months


def parse_order_datetime(value):
    if isinstance(value, datetime):
        return value

    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", ""))
    except ValueError:
        return None


def build_summary_sections(orders: list) -> list:
    month_defs = get_last_12_months_desc()
    month_keys = {item["key"] for item in month_defs}

    def init_month_map():
        return {item["key"]: {"label": item["label"], "orders": []} for item in month_defs}

    section_configs = [
        {"key": "delivered", "label": "Delivered"},
        {"key": "cancelled", "label": "Cancelled"},
        {"key": "returned_by_buyer", "label": "Returned by buyer"},
    ]
    section_maps = {section["key"]: init_month_map() for section in section_configs}

    for order in orders:
        order_date = parse_order_datetime(order.get("OrderDate"))
        if not order_date:
            continue

        month_key = f"{order_date.year:04d}-{order_date.month:02d}"
        if month_key not in month_keys:
            continue

        order_status = str(order.get("OrderStatus", "") or "").strip().lower()
        delivery_status = str(order.get("DeliveryStatus", "") or "").strip().lower()

        section_key = None
        if delivery_status == "delivered":
            section_key = "delivered"
        elif order_status == "cancelled":
            section_key = "cancelled"
        elif delivery_status == "returned by buyer":
            section_key = "returned_by_buyer"

        if section_key:
            section_maps[section_key][month_key]["orders"].append(order)

    sections = []
    for section in section_configs:
        months = []
        section_total = 0

        for month in month_defs:
            month_orders = section_maps[section["key"]][month["key"]]["orders"]
            months.append(
                {
                    "key": month["key"],
                    "label": section_maps[section["key"]][month["key"]]["label"],
                    "count": len(month_orders),
                    "orders": month_orders,
                }
            )
            section_total += len(month_orders)

        sections.append(
            {
                "key": section["key"],
                "label": section["label"],
                "total": section_total,
                "months": months,
            }
        )

    return sections


def build_dashboard_kpis(all_orders: list, active_orders: list) -> dict:
    revenue = sum(
        float(order.get("TotalAmount", 0) or 0)
        for order in all_orders
        if str(order.get("DeliveryStatus", "") or "").strip().lower() == "delivered"
    )
    cancelled_or_returned = sum(
        1
        for order in all_orders
        if (str(order.get("OrderStatus", "") or "").strip().lower() == "cancelled")
        or (str(order.get("DeliveryStatus", "") or "").strip().lower() == "returned by buyer")
    )
    return {
        "total": len(all_orders),
        "pending": len(active_orders),
        "confirmed": sum(
            1
            for order in all_orders
            if str(order.get("OrderStatus", "") or "").strip().lower() == "confirmed"
        ),
        "cancelled_or_returned": cancelled_or_returned,
        "revenue": revenue,
    }


def place_public_order(payload: dict) -> dict:
    conn = get_db_connection()
    conn.autocommit = False

    domain_name = normalize_domain_name(payload["domain_name"])
    buyer_name = payload["buyer_name"].strip()
    phone = payload["phone"].strip()
    address = payload["address"].strip()
    total_amount = Decimal(payload["total_amount"])

    try:
        cursor = conn.cursor()
        cursor.execute("SET XACT_ABORT ON;")
        cursor.execute(
            """
            SELECT TOP 1 S.SellerID, S.BusinessName, Org.OrganizationID
            FROM Sellers S WITH (UPDLOCK, HOLDLOCK)
            INNER JOIN Organizations Org ON Org.LegacySellerID = S.SellerID
            WHERE S.DomainName = ?
            """,
            (domain_name,),
        )
        seller = cursor.fetchone()
        if not seller:
            raise LookupError("SELLER_NOT_FOUND")

        seller_id = int(seller.SellerID)
        organization_id = str(seller.OrganizationID)

        # Reuse existing buyer by WhatsApp/phone so one number maps to one BuyerID per seller.
        cursor.execute(
            """
            SELECT TOP 1 BuyerID, SellerBuyerNo
            FROM Buyers WITH (UPDLOCK, HOLDLOCK)
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
                FROM Buyers WITH (UPDLOCK, HOLDLOCK)
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
            FROM Orders WITH (UPDLOCK, HOLDLOCK)
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
            "organization_id": organization_id,
            "business_name": seller.BusinessName,
            "domain_name": domain_name,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def place_demo_order(payload: dict) -> dict:
    if not DEMO_MODE or not DEMO_USERS:
        raise LookupError("SELLER_NOT_FOUND")
    demo_user = next(iter(DEMO_USERS.values()))
    if payload["domain_name"] != demo_user["domain_name"]:
        raise LookupError("SELLER_NOT_FOUND")

    seller_id = int(demo_user["seller_id"])
    matching_buyers = [
        row for row in DEMO_ORDERS if row["SellerID"] == seller_id and row["Phone"] == payload["phone"]
    ]
    if matching_buyers:
        buyer_id = int(matching_buyers[0]["BuyerID"])
        seller_buyer_no = int(matching_buyers[0]["SellerBuyerNo"])
    else:
        seller_buyer_no = max(
            (int(row["SellerBuyerNo"]) for row in DEMO_ORDERS if row["SellerID"] == seller_id),
            default=0,
        ) + 1
        buyer_id = max((int(row["BuyerID"]) for row in DEMO_ORDERS), default=0) + 1

    seller_order_no = max(
        (int(row["SellerOrderNo"]) for row in DEMO_ORDERS if row["SellerID"] == seller_id),
        default=0,
    ) + 1
    order_id = max((int(row["OrderID"]) for row in DEMO_ORDERS), default=0) + 1
    DEMO_ORDERS.append(
        {
            "OrderID": order_id,
            "SellerID": seller_id,
            "SellerOrderNo": seller_order_no,
            "BuyerID": buyer_id,
            "SellerBuyerNo": seller_buyer_no,
            "BuyerName": payload["buyer_name"],
            "Phone": payload["phone"],
            "DeliveryAddress": payload["address"],
            "TotalAmount": payload["total_amount"],
            "OrderStatus": "Pending",
            "DeliveryStatus": None,
            "ActionTaken": "Pending review",
            "OrderDate": datetime.now(),
        }
    )
    return {
        "order_id": order_id,
        "seller_order_no": seller_order_no,
        "buyer_id": buyer_id,
        "seller_buyer_no": seller_buyer_no,
        "seller_id": seller_id,
        "organization_id": demo_user.get("organization_id", DEMO_ORGANIZATION_ID),
        "business_name": demo_user["business_name"],
        "domain_name": demo_user["domain_name"],
    }


def update_demo_order(order_id: int, seller_id: int, *, action: str | None = None, status: str | None = None) -> bool:
    for order in DEMO_ORDERS:
        if int(order["OrderID"]) != order_id or int(order["SellerID"]) != seller_id:
            continue
        if action and order["OrderStatus"] == "Pending":
            order["OrderStatus"] = "Confirmed" if action == "confirm" else "Cancelled"
            order["DeliveryStatus"] = "Pending" if action == "confirm" else None
            order["ActionTaken"] = "Confirmed by seller" if action == "confirm" else "Not confirmed by seller"
            return True
        if status and order["OrderStatus"] == "Confirmed" and order["DeliveryStatus"] == "Pending":
            order["DeliveryStatus"] = status
            return True
        return False
    return False


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

        session.clear()
        session["user"] = build_user_session(db_login["user"])
        session.permanent = True
        get_csrf_token()
        return redirect(url_for("dashboard"))
    except Exception as err:
        app.logger.error("Database login check failed: %s", err)

        if not DEMO_MODE:
            if is_missing_auth_table(err):
                flash("Login table is missing. Run the database setup or migration first.", "error")
            else:
                flash("Database login is unavailable. Check the server configuration.", "error")
            return render_template("login.html", email=email, username=username)

        demo_login = login_with_demo_user(email, username, password)
        if not demo_login.get("ok"):
            flash(demo_login.get("message", "Invalid username or password."), "warn" if demo_login.get("status") == 423 else "error")
            return render_template("login.html", email=email, username=username)

        session.clear()
        session["user"] = build_user_session(demo_login["user"])
        session.permanent = True
        get_csrf_token()
        flash("Logged in to isolated demo mode. Demo changes are not persisted.", "warn")
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

    validation_error = validate_signup_payload(payload)
    if validation_error:
        flash(validation_error, "error")
        return render_template("signup.html", form=payload)

    try:
        created_user = signup_with_database(payload)
        session.clear()
        session["user"] = build_user_session(created_user)
        session.permanent = True
        get_csrf_token()
        flash("Signup successful.", "success")
        return redirect(url_for("dashboard"))
    except ValueError as err:
        code = str(err)
        if code == "WHATSAPP_ALREADY_LINKED":
            flash("This WhatsApp number is already linked to another business.", "warn")
        elif code == "DOMAIN_ALREADY_LINKED":
            flash("This domain is already linked to another seller.", "warn")
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
@require_permission("dashboard.view")
def dashboard():
    user = session["user"]
    search = str(request.args.get("search", "")).strip()
    all_orders, source = fetch_orders_for_dashboard(
        user["seller_id"],
        user["organization_id"],
        apply_search=False,
        allow_demo=user.get("is_demo", False),
        global_user_id=user.get("global_user_id"),
    )
    active_orders = [order for order in all_orders if is_active_dashboard_order(order)]
    active_orders = filter_dashboard_orders(active_orders, search)
    kpis = build_dashboard_kpis(all_orders, active_orders)

    return render_template(
        "dashboard.html",
        user=user,
        orders=active_orders,
        kpis=kpis,
        search=search,
        source=source,
    )


@app.get("/summary")
@require_permission("summary.view")
def summary_page():
    user = session["user"]
    all_orders, source = fetch_orders_for_dashboard(
        user["seller_id"],
        user["organization_id"],
        apply_search=False,
        allow_demo=user.get("is_demo", False),
        global_user_id=user.get("global_user_id"),
        required_permission="summary.view",
    )
    active_orders = [order for order in all_orders if is_active_dashboard_order(order)]
    summary_sections = build_summary_sections(all_orders)
    kpis = build_dashboard_kpis(all_orders, active_orders)

    return render_template(
        "summary.html",
        user=user,
        summary_sections=summary_sections,
        kpis=kpis,
        source=source,
    )


@app.post("/organizations/switch")
@require_permission("organizations.switch")
def switch_organization():
    if session["user"].get("is_demo"):
        abort(403)
    try:
        requested = str(UUID(request.form.get("organization_id", "")))
    except (ValueError, TypeError, AttributeError):
        abort(400, description="Invalid organization selection.")
    # The supplied ID is only a selection; authority comes from the fresh DB lookup
    # performed by require_auth, never from the form or cached session memberships.
    selected = next((item for item in g.organization_memberships
                     if item["organization_id"].lower() == requested), None)
    if selected is None:
        abort(403)
    # A roleless target is not a usable selection; query target permission again.
    conn = get_db_connection()
    try:
        allowed = conn.cursor().execute(
            """SELECT 1 FROM OrganizationMemberships M JOIN RolePermissions RP ON RP.RoleName=M.RoleName
               JOIN Users U ON U.UserID=M.UserID
               WHERE M.UserID=? AND M.OrganizationID=? AND M.Status='Active'
                 AND U.IsActive=1 AND U.IsLocked=0 AND U.FailedAttempts<3
                 AND RP.Permission='organizations.switch'""",
            (selected["global_user_id"], requested),
        ).fetchone()
        if not allowed:
            abort(403)
    finally:
        conn.close()
    session.clear()
    session["user"] = build_user_session(selected)
    session.permanent = True
    get_csrf_token()
    return redirect(url_for("dashboard"))


@app.get("/organization/members")
@require_permission("members.view")
def organization_members():
    user = session["user"]
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        rows = cursor.execute(
            """SELECT U.UserID, U.Username, M.Status, M.RoleName
               FROM OrganizationMemberships M JOIN Users U ON U.UserID=M.UserID
               WHERE M.OrganizationID=? AND EXISTS (
                   SELECT 1 FROM OrganizationMemberships A JOIN Users Actor ON Actor.UserID=A.UserID
                   JOIN RolePermissions RP ON RP.RoleName=A.RoleName
                   WHERE A.OrganizationID=M.OrganizationID AND A.UserID=? AND A.Status='Active'
                     AND Actor.IsActive=1 AND Actor.IsLocked=0 AND Actor.FailedAttempts<3
                     AND RP.Permission='members.view') ORDER BY U.Username""",
            (user["organization_id"], user["global_user_id"]),
        ).fetchall()
        roles = [row[0] for row in cursor.execute("SELECT RoleName FROM Roles ORDER BY RoleName").fetchall()]
        invitations = []
        if g.role_name == 'Owner' and has_permission('members.roles'):
            lock_organization_owner(cursor, user['organization_id'], user['global_user_id'])
            invitations = cursor.execute("""SELECT InvitationID, Email, RoleName, ExpiresAt,
                CASE WHEN Status='Pending' AND ExpiresAt<=SYSUTCDATETIME() THEN 'Expired'
                     ELSE Status END AS Status FROM OrganizationInvitations
                WHERE OrganizationID=? ORDER BY CreatedAt DESC""", (user['organization_id'],)).fetchall()
        return render_template("members.html", user=user, members=rows, roles=roles,
                               invitations=invitations, invite_roles=INVITABLE_ROLES,
                               invitation_development=development_invitation_delivery())
    finally:
        conn.close()


@app.post("/organization/members/<int:member_id>/role")
@require_permission("members.roles")
def change_member_role(member_id: int):
    user = session["user"]
    role = request.form.get("role", "")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Serialize role administration per organization, including last-owner checks.
        cursor.execute("SELECT OrganizationID FROM Organizations WITH (UPDLOCK,HOLDLOCK) WHERE OrganizationID=?",
                       (user["organization_id"],)).fetchone()
        actor = cursor.execute(
            """SELECT M.UserID FROM OrganizationMemberships M WITH (UPDLOCK,HOLDLOCK)
               JOIN Users U WITH (UPDLOCK,HOLDLOCK) ON U.UserID=M.UserID
               JOIN RolePermissions RP WITH (HOLDLOCK) ON RP.RoleName=M.RoleName
               WHERE M.OrganizationID=? AND M.UserID=? AND M.Status='Active'
                 AND U.IsActive=1 AND U.IsLocked=0 AND U.FailedAttempts<3
                 AND RP.Permission='members.roles'""",
            (user["organization_id"], user["global_user_id"]),
        ).fetchone()
        if not actor:
            abort(403)
        if not cursor.execute("SELECT 1 FROM Roles WHERE RoleName=?", (role,)).fetchone():
            abort(400, description="Unknown role.")
        target = cursor.execute(
            """SELECT RoleName FROM OrganizationMemberships WITH (UPDLOCK,HOLDLOCK)
               WHERE OrganizationID=? AND UserID=? AND Status='Active'""",
            (user["organization_id"], member_id),
        ).fetchone()
        if not target:
            abort(404)
        if target.RoleName == "Owner" and role != "Owner":
            other_owners = cursor.execute(
                """SELECT COUNT(*) FROM OrganizationMemberships M WITH (UPDLOCK,HOLDLOCK)
                   JOIN Users U WITH (UPDLOCK,HOLDLOCK) ON U.UserID=M.UserID
                   WHERE M.OrganizationID=? AND M.UserID<>? AND M.Status='Active'
                     AND M.RoleName='Owner' AND U.IsActive=1 AND U.IsLocked=0 AND U.FailedAttempts<3""",
                (user["organization_id"], member_id),
            ).fetchone()[0]
            if not other_owners:
                abort(409, description="Keep at least one active, unlocked Owner.")
        cursor.execute("UPDATE OrganizationMemberships SET RoleName=? WHERE OrganizationID=? AND UserID=? AND Status='Active'",
                       (role, user["organization_id"], member_id))
        conn.commit()
    except pyodbc.Error:
        conn.rollback()
        app.logger.error("Role change failed due to a database error.")
        abort(503)
    finally:
        conn.close()
    return redirect(url_for("organization_members"))


INVITABLE_ROLES = ('Admin', 'Operations', 'Finance', 'Marketing', 'Support')


def invitation_digest(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def development_invitation_delivery() -> bool:
    # An explicit local-only escape hatch, never inferred from mail failure or demo.
    return (os.getenv('APP_ENV') == 'development' and env_flag('DEV_INVITATION_LINKS')
            and request.remote_addr in {'127.0.0.1', '::1'})


def send_invitation_email(recipient: str, subject: str, body: str):
    """SMTP with mandatory verified STARTTLS. Never log message bodies or errors."""
    host, sender = os.getenv('SMTP_HOST'), os.getenv('SMTP_FROM')
    if not host or not sender:
        raise RuntimeError('Email delivery is not configured')
    message = EmailMessage()
    message['From'], message['To'], message['Subject'] = sender, recipient, subject
    message.set_content(body)
    with smtplib.SMTP(host, env_int('SMTP_PORT', 587, 1, 65535), timeout=10) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        if os.getenv('SMTP_USERNAME'):
            smtp.login(os.environ['SMTP_USERNAME'], os.getenv('SMTP_PASSWORD', ''))
        smtp.send_message(message)


def invitation_link(token: str) -> str:
    origin = os.getenv('APP_PUBLIC_URL', '').rstrip('/')
    parts = urlsplit(origin)
    if parts.scheme != 'https' or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment or parts.path:
        raise ValueError('APP_PUBLIC_URL must be a fixed HTTPS origin')
    # Fragment never reaches access logs or the Referer header. The accept page
    # moves it to a POST field and clears browser history before any submission.
    return origin + url_for('accept_invitation') + '#token=' + token


def lock_organization_owner(cursor, organization_id, user_id):
    cursor.execute('SELECT OrganizationID FROM Organizations WITH (UPDLOCK,HOLDLOCK) WHERE OrganizationID=?',
                   (organization_id,)).fetchone()
    owner = cursor.execute("""SELECT M.UserID FROM OrganizationMemberships M WITH (UPDLOCK,HOLDLOCK)
        JOIN Users U WITH (UPDLOCK,HOLDLOCK) ON U.UserID=M.UserID
        JOIN RolePermissions RP WITH (HOLDLOCK) ON RP.RoleName=M.RoleName
        WHERE M.OrganizationID=? AND M.UserID=? AND M.Status='Active' AND M.RoleName='Owner'
          AND U.IsActive=1 AND U.IsLocked=0 AND U.FailedAttempts<3 AND RP.Permission='members.roles'""",
        (organization_id, user_id)).fetchone()
    if not owner:
        abort(403, description='An active Owner is required.')


@app.post('/organization/invitations')
@require_permission('members.roles')
def create_invitation():
    email = request.form.get('email', '').strip().lower()
    role = request.form.get('role', '')
    if not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', email) or len(email)>255 or role not in INVITABLE_ROLES:
        abort(400, description='Enter a valid email and a permitted non-Owner role.')
    user = session['user']
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        lock_organization_owner(cursor, user['organization_id'], user['global_user_id'])
        # Any previous membership requires a separate reviewed recovery process;
        # invitations never overwrite roles or reactivate revoked membership.
        if cursor.execute("""SELECT 1 FROM OrganizationMemberships M JOIN Users U ON U.UserID=M.UserID
            WHERE M.OrganizationID=? AND U.NormalizedEmail=?""", (user['organization_id'], email)).fetchone():
            abort(409, description='This identity already has a membership; invitations cannot reactivate it.')
        cursor.execute("""UPDATE OrganizationInvitations SET Status='Expired', VerificationHash=NULL,
            VerificationExpiresAt=NULL WHERE OrganizationID=? AND Email=? AND Status='Pending'
            AND ExpiresAt<=SYSUTCDATETIME()""", (user['organization_id'], email))
        if cursor.execute("""SELECT 1 FROM OrganizationInvitations WHERE OrganizationID=? AND Email=? AND Status='Pending'""",
                          (user['organization_id'], email)).fetchone():
            abort(409, description='A pending invitation already exists. Revoke it before sending another.')
        token = secrets.token_urlsafe(32)
        cursor.execute("""INSERT OrganizationInvitations
            (OrganizationID,Email,RoleName,TokenHash,CreatedByUserID,ExpiresAt)
            VALUES (?,?,?,?,?,DATEADD(hour,48,SYSUTCDATETIME()))""",
            (user['organization_id'], email, role, invitation_digest(token), user['global_user_id']))
        if development_invitation_delivery():
            link = url_for('accept_invitation') + '#token=' + token
        else:
            send_invitation_email(email, 'Your DukaanDesk employee invitation',
                'You were invited to an organization as ' + role + '. This invitation expires in 48 hours.\n'
                + invitation_link(token) + '\nSign in with the matching account, or verify your mailbox to register.')
            link = None
        conn.commit()
        if link:
            return render_template('invitation_created.html', link=link), 201
        flash('Invitation sent. It expires in 48 hours.', 'success')
        return redirect(url_for('organization_members'))
    except pyodbc.IntegrityError:
        conn.rollback()
        abort(409, description='An invitation or membership already exists.')
    except (pyodbc.Error, OSError, smtplib.SMTPException, RuntimeError, ValueError):
        conn.rollback()
        app.logger.error('Invitation creation or delivery failed; no invitation was committed.')
        abort(503, description='Invitation delivery is unavailable. Contact your administrator.')
    finally:
        conn.close()


@app.post('/organization/invitations/<uuid:invitation_id>/revoke')
@require_permission('members.roles')
def revoke_invitation(invitation_id):
    user = session['user']
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        lock_organization_owner(cursor, user['organization_id'], user['global_user_id'])
        row = cursor.execute("""SELECT Status FROM OrganizationInvitations WITH (UPDLOCK,HOLDLOCK)
            WHERE InvitationID=? AND OrganizationID=?""", (str(invitation_id), user['organization_id'])).fetchone()
        if not row:
            abort(404)
        if row.Status != 'Pending':
            abort(409, description='Only pending invitations can be revoked.')
        cursor.execute("""UPDATE OrganizationInvitations SET Status=CASE WHEN ExpiresAt<=SYSUTCDATETIME()
            THEN 'Expired' ELSE 'Revoked' END, VerificationHash=NULL, VerificationExpiresAt=NULL
            WHERE InvitationID=? AND OrganizationID=?""", (str(invitation_id), user['organization_id']))
        conn.commit()
        return redirect(url_for('organization_members'))
    finally:
        conn.close()


@app.post('/organization/members/<int:member_id>/deactivate')
@require_permission('members.roles')
def deactivate_member(member_id):
    user = session['user']
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        lock_organization_owner(cursor, user['organization_id'], user['global_user_id'])
        target = cursor.execute("""SELECT RoleName FROM OrganizationMemberships WITH (UPDLOCK,HOLDLOCK)
            WHERE OrganizationID=? AND UserID=? AND Status='Active'""", (user['organization_id'], member_id)).fetchone()
        if not target:
            abort(404)
        if target.RoleName == 'Owner' and not cursor.execute("""SELECT 1 FROM OrganizationMemberships M WITH (UPDLOCK,HOLDLOCK)
            JOIN Users U WITH (UPDLOCK,HOLDLOCK) ON U.UserID=M.UserID
            WHERE M.OrganizationID=? AND M.UserID<>? AND M.Status='Active' AND M.RoleName='Owner'
              AND U.IsActive=1 AND U.IsLocked=0 AND U.FailedAttempts<3""", (user['organization_id'], member_id)).fetchone():
            abort(409, description='Keep at least one active, unlocked Owner.')
        cursor.execute("UPDATE OrganizationMemberships SET Status='Inactive' WHERE OrganizationID=? AND UserID=?",
                       (user['organization_id'], member_id))
        conn.commit()
        return redirect(url_for('organization_members'))
    finally:
        conn.close()


@app.route('/invitations/accept', methods=['GET', 'POST'])
def accept_invitation():
    if request.method == 'GET':
        return render_template('invitation_accept.html')
    token = request.form.get('token', '')
    action = request.form.get('action', '')
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token) or action not in {'accept', 'verify', 'register'}:
        abort(400, description='A valid invitation token and action are required.')
    # Existing-user acceptance requires a freshly resolved, non-demo identity.
    if action == 'accept' and (not session.get('user') or session['user'].get('is_demo')
                               or not resolve_legacy_organization_context()):
        abort(403, description='Sign in with the invited email address first, then reopen the invitation.')
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        locator = cursor.execute('SELECT OrganizationID FROM OrganizationInvitations WHERE TokenHash=?',
                                 (invitation_digest(token),)).fetchone()
        if not locator:
            abort(404, description='Invitation unavailable.')
        # All invitation and membership administration locks organization first.
        cursor.execute('SELECT OrganizationID FROM Organizations WITH (UPDLOCK,HOLDLOCK) WHERE OrganizationID=?',
                       (locator.OrganizationID,)).fetchone()
        invite = cursor.execute("""SELECT *, CASE WHEN ExpiresAt<=SYSUTCDATETIME() THEN 1 ELSE 0 END AS IsExpired,
            CASE WHEN VerificationExpiresAt>SYSUTCDATETIME() THEN 1 ELSE 0 END AS VerificationValid,
            CASE WHEN VerificationSentAt>DATEADD(second,-60,SYSUTCDATETIME()) THEN 1 ELSE 0 END AS RecentlySent
            FROM OrganizationInvitations WITH (UPDLOCK,HOLDLOCK) WHERE TokenHash=?""",
            (invitation_digest(token),)).fetchone()
        if invite.Status != 'Pending':
            abort(410, description='Invitation is no longer pending.')
        if invite.IsExpired:
            cursor.execute("""UPDATE OrganizationInvitations SET Status='Expired',VerificationHash=NULL,
                VerificationExpiresAt=NULL WHERE InvitationID=?""", (invite.InvitationID,))
            conn.commit()
            abort(410, description='Invitation expired.')
        lock_organization_owner(cursor, invite.OrganizationID, invite.CreatedByUserID)
        if invite.RoleName not in INVITABLE_ROLES:
            abort(403)
        existing = cursor.execute("""SELECT UserID,IsActive,IsLocked,FailedAttempts FROM Users WITH (UPDLOCK,HOLDLOCK)
            WHERE NormalizedEmail=?""", (invite.Email,)).fetchone()
        if existing and cursor.execute('SELECT 1 FROM OrganizationMemberships WHERE OrganizationID=? AND UserID=?',
                                       (invite.OrganizationID, existing.UserID)).fetchone():
            abort(409, description='Membership already exists; no role or status was changed.')
        # Legacy business signup does not verify email. Therefore even an
        # authenticated match must prove mailbox control, preventing signup with
        # the invited address from laundering link possession into verification.
        if action == 'verify':
            if invite.RecentlySent:
                abort(429, description='Wait one minute before requesting another verification code.')
            verification = secrets.token_urlsafe(32)
            send_invitation_email(invite.Email, 'Verify your DukaanDesk email',
                'Use this separate verification code only if you requested employee membership.\n'
                + verification + '\nIt expires in 15 minutes. This is not your invitation token.')
            cursor.execute("""UPDATE OrganizationInvitations SET VerificationHash=?,
                VerificationExpiresAt=DATEADD(minute,15,SYSUTCDATETIME()),VerificationSentAt=SYSUTCDATETIME()
                WHERE InvitationID=?""", (invitation_digest(verification), invite.InvitationID))
            conn.commit()
            return render_template('invitation_accept.html', token=token,
                                   notice='Verification code sent to the invited mailbox. It expires in 15 minutes.')
        verification = request.form.get('verification', '')
        if (not invite.VerificationValid or not invite.VerificationHash
            or not hmac.compare_digest(invite.VerificationHash, invitation_digest(verification))):
            abort(403, description='A separate, valid emailed verification code is required.')
        if action == 'accept':
            user = session['user']
            if not existing or existing.UserID != user['global_user_id'] or not existing.IsActive or existing.IsLocked or existing.FailedAttempts>=3:
                abort(403, description='Sign in with the invited email address.')
            # Recheck the authenticating membership within this transaction too.
            if not cursor.execute("""SELECT 1 FROM OrganizationMemberships WITH (UPDLOCK,HOLDLOCK)
                WHERE UserID=? AND OrganizationID=? AND Status='Active'""",
                (existing.UserID, user['organization_id'])).fetchone():
                abort(403)
            accepted_user_id = existing.UserID
        else:
            if existing:
                abort(409, description='This email already has an account. Sign in to accept; registration cannot merge accounts.')
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            if not USERNAME_RE.fullmatch(username) or not 10<=len(password)<=128 or password != request.form.get('confirm_password'):
                abort(400, description='Use a valid username and matching passwords of 10–128 characters.')
            # No seller or legacy account is invented for an invited employee.
            accepted_user_id = cursor.execute("""INSERT Users (Email,Username,PasswordHash)
                OUTPUT inserted.UserID VALUES (?,?,?)""",
                (invite.Email, username, generate_password_hash(password))).fetchone()[0]
        cursor.execute("""INSERT OrganizationMemberships (UserID,OrganizationID,Status,RoleName)
            VALUES (?,?,'Active',?)""", (accepted_user_id, invite.OrganizationID, invite.RoleName))
        cursor.execute("""UPDATE OrganizationInvitations SET Status='Accepted',AcceptedByUserID=?,
            AcceptedAt=SYSUTCDATETIME(),VerificationHash=NULL,VerificationExpiresAt=NULL WHERE InvitationID=?""",
            (accepted_user_id, invite.InvitationID))
        conn.commit()
        if action == 'register':
            session.clear()
        flash('Invitation accepted. Sign in or select the organization to continue.', 'success')
        return redirect(url_for('dashboard' if action == 'accept' else 'login'))
    except pyodbc.IntegrityError:
        conn.rollback()
        abort(409, description='An account or membership already exists; nothing was merged.')
    except (pyodbc.Error, OSError, smtplib.SMTPException, RuntimeError, ValueError):
        conn.rollback()
        app.logger.error('Invitation acceptance or verification delivery failed.')
        abort(503, description='Email or database service unavailable. New registration requires email verification.')
    finally:
        conn.close()


@app.post("/orders/<int:order_id>/action")
@require_permission("orders.decide")
def update_order_action(order_id: int):
    action = str(request.form.get("action", "")).strip().lower()
    if action not in {"confirm", "not_confirm"}:
        flash("Action must be confirm or not_confirm.", "error")
        return redirect(url_for("dashboard", search=request.form.get("search", "")))

    next_status = "Confirmed" if action == "confirm" else "Cancelled"
    next_delivery_status = "Pending" if action == "confirm" else None

    if session["user"].get("is_demo"):
        updated = update_demo_order(
            order_id, session["user"]["seller_id"], action=action
        )
        flash("Demo order action updated." if updated else "Only pending demo orders can be updated.", "success" if updated else "warn")
        return redirect(url_for("dashboard", search=request.form.get("search", "")))

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
              AND EXISTS (
                  SELECT 1
                  FROM Organizations Org
                  JOIN OrganizationMemberships M ON M.OrganizationID = Org.OrganizationID
                  JOIN Users U ON U.UserID = M.UserID
                  WHERE Org.LegacySellerID = Orders.SellerID
                    AND Org.OrganizationID = ?
                    AND M.UserID = ? AND M.Status = 'Active' AND U.IsActive = 1
                    AND U.IsLocked = 0 AND U.FailedAttempts < 3
                    AND EXISTS (SELECT 1 FROM RolePermissions RP WHERE RP.RoleName=M.RoleName
                                AND RP.Permission='orders.decide')
              )
              AND OrderStatus = 'Pending'
              AND DeliveryStatus IS NULL
            """,
            (
                next_status,
                next_delivery_status,
                order_id,
                session["user"]["seller_id"],
                session["user"]["organization_id"],
                session["user"]["global_user_id"],
            ),
        )
        rows_affected = cursor.rowcount

        if rows_affected <= 0:
            conn.rollback()
            flash("Only this seller's pending orders can be confirmed or cancelled.", "warn")
        else:
            cursor.execute(
                """
                INSERT INTO MessageLogs (OrderID, MessageContent)
                VALUES (?, ?)
                """,
                (order_id, f"Seller changed order status to {next_status}."),
            )
            conn.commit()
            flash("Order action updated.", "success")
    except Exception as err:
        if conn:
            conn.rollback()
        app.logger.error("Order action update failed: %s", err)
        flash("Unable to update order action right now.", "error")
    finally:
        if conn:
            conn.close()

    return redirect(url_for("dashboard", search=request.form.get("search", "")))


@app.post("/orders/<int:order_id>/status")
@require_permission("orders.delivery")
def update_order_status(order_id: int):
    status = str(request.form.get("status", "")).strip().lower()
    status_map = {"delivered": "Delivered", "returned_by_buyer": "Returned by buyer"}
    next_delivery_status = status_map.get(status)

    if not next_delivery_status:
        flash("Status must be delivered or returned_by_buyer.", "error")
        return redirect(url_for("dashboard", search=request.form.get("search", "")))

    if session["user"].get("is_demo"):
        updated = update_demo_order(
            order_id,
            session["user"]["seller_id"],
            status=next_delivery_status,
        )
        flash("Demo delivery status updated." if updated else "Only confirmed demo orders awaiting delivery can be updated.", "success" if updated else "warn")
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
              AND EXISTS (
                  SELECT 1
                  FROM Organizations Org
                  JOIN OrganizationMemberships M ON M.OrganizationID = Org.OrganizationID
                  JOIN Users U ON U.UserID = M.UserID
                  WHERE Org.LegacySellerID = Orders.SellerID
                    AND Org.OrganizationID = ?
                    AND M.UserID = ? AND M.Status = 'Active' AND U.IsActive = 1
                    AND U.IsLocked = 0 AND U.FailedAttempts < 3
                    AND EXISTS (SELECT 1 FROM RolePermissions RP WHERE RP.RoleName=M.RoleName
                                AND RP.Permission='orders.delivery')
              )
              AND OrderStatus = 'Confirmed'
              AND DeliveryStatus = 'Pending'
            """,
            (
                next_delivery_status,
                order_id,
                session["user"]["seller_id"],
                session["user"]["organization_id"],
                session["user"]["global_user_id"],
            ),
        )
        rows_affected = cursor.rowcount

        if rows_affected <= 0:
            conn.rollback()
            flash("Only confirmed orders with pending status can be updated.", "warn")
        else:
            cursor.execute(
                """
                INSERT INTO MessageLogs (OrderID, MessageContent)
                VALUES (?, ?)
                """,
                (order_id, f"Seller changed delivery status to {next_delivery_status}."),
            )
            conn.commit()
            flash("Delivery status updated.", "success")
    except Exception as err:
        if conn:
            conn.rollback()
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

    payload["total_amount"] = parse_order_amount(payload["total_amount"])
    validation_error = validate_order_payload(payload)
    if validation_error:
        flash(validation_error, "error")
        return render_template("store.html", domain_name=payload["domain_name"], form=payload)

    try:
        demo_domains = {user["domain_name"] for user in DEMO_USERS.values()}
        result = place_demo_order(payload) if DEMO_MODE and payload["domain_name"] in demo_domains else place_public_order(payload)
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


@app.get("/summary.html")
def summary_html_redirect():
    return redirect(url_for("summary_page"))


@app.get("/store.html")
def store_html_redirect():
    return redirect(url_for("store"))


if __name__ == "__main__":
    app.run(
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "3000")),
        debug=env_flag("FLASK_DEBUG", False),
    )
