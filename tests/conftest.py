"""
Shared pytest fixtures for all test types.
The DB_PATH env var MUST be set before app.py is imported,
because init_db() runs at module load time.
"""
import os
import tempfile
import sys

# --- Must happen before app import ---
_db_fd, _DB_PATH = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)
os.environ["DB_PATH"] = _DB_PATH
os.environ["SECRET_KEY"] = "test-secret-key-do-not-use-in-prod"

# Add project root to path so `import app` works
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import gc
import sqlite3 as _sqlite3
import pytest
from werkzeug.security import generate_password_hash

from app import app as flask_app, init_db, get_db


# ---------------------------------------------------------------------------
# Session-scoped DB setup / teardown
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initialize the schema, enable WAL mode, and seed data once per session."""
    init_db()
    # Enable WAL journal mode so concurrent connections don't block each other.
    # This prevents "database is locked" when a Flask route leaves a connection
    # open (e.g., after an IntegrityError skips conn.close()).
    conn = _sqlite3.connect(_DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    yield
    try:
        os.unlink(_DB_PATH)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Per-test DB isolation
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_db():
    """
    Run each test against a clean slate.
    We truncate mutable data but keep the admin user, default categories,
    and default settings created by init_db().
    """
    yield  # let the test run first (setup may insert data too)

    # Force GC to close any lingering DB connections from Flask route handlers
    # that may have raised an exception before calling conn.close().
    gc.collect()

    conn = _sqlite3.connect(_DB_PATH, timeout=15)
    conn.row_factory = _sqlite3.Row
    c = conn.cursor()
    c.execute("DELETE FROM financial_items")
    c.execute(
        "DELETE FROM categories WHERE name NOT IN "
        "('Mortgage','Insurance','Utilities','Subscriptions','Warranties','ISA','Pension','Other')"
    )
    c.execute("DELETE FROM users WHERE email != 'admin@policytracker.local'")

    # Re-seed default categories in case a backup-restore test wiped them
    _default_categories = [
        ("Mortgage", "#10B981"),
        ("Insurance", "#3B82F6"),
        ("Utilities", "#F59E0B"),
        ("Subscriptions", "#8B5CF6"),
        ("Warranties", "#EC4899"),
        ("ISA", "#14B8A6"),
        ("Pension", "#F97316"),
        ("Other", "#6B7280"),
    ]
    for _name, _color in _default_categories:
        c.execute(
            "INSERT OR IGNORE INTO categories (name, color) VALUES (?, ?)",
            (_name, _color),
        )

    # Reset settings to defaults so tests are idempotent
    c.execute("UPDATE settings SET value='30' WHERE key='notification_days'")
    c.execute("UPDATE settings SET value='true' WHERE key='notification_enabled'")
    c.execute("UPDATE settings SET value='$' WHERE key='currency_symbol'")
    c.execute("UPDATE settings SET value='USD' WHERE key='currency_code'")
    # Re-seed settings in case a restore wiped them
    _default_settings = [
        ("notification_days", "30"),
        ("notification_enabled", "true"),
        ("smtp_server", ""),
        ("smtp_port", "587"),
        ("smtp_username", ""),
        ("smtp_password", ""),
        ("smtp_from_email", ""),
        ("smtp_use_tls", "true"),
        ("currency_symbol", "$"),
        ("currency_code", "USD"),
    ]
    for _key, _val in _default_settings:
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (_key, _val))

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Flask test client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Logged-in test client (admin user)."""
    client.post(
        "/login",
        data={"email": "admin@policytracker.local", "password": "admin"},
        follow_redirects=True,
    )
    yield client


# ---------------------------------------------------------------------------
# Helper fixtures for data creation
# ---------------------------------------------------------------------------

@pytest.fixture
def regular_user():
    """Create and return a regular (non-admin) user."""
    conn = get_db()
    c = conn.cursor()
    hashed = generate_password_hash("testpass123")
    c.execute(
        "INSERT INTO users (email, password, is_admin, enabled) VALUES (?, ?, ?, ?)",
        ("user@example.com", hashed, 0, 1),
    )
    conn.commit()
    user_id = c.lastrowid
    conn.close()
    return {"email": "user@example.com", "password": "testpass123", "id": user_id}


@pytest.fixture
def user_client(client, regular_user):
    """Logged-in test client (regular user)."""
    client.post(
        "/login",
        data={"email": regular_user["email"], "password": regular_user["password"]},
        follow_redirects=True,
    )
    yield client


@pytest.fixture
def sample_policy():
    """Insert a sample policy and return its id."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO financial_items
           (type, name, policy_number, insurer, category, start_date, end_date,
            monthly_amount, annual_amount, frequency, is_fixed_cost, is_policy)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "expense", "Home Insurance", "POL-001", "Acme Insurers",
            "Insurance", "2024-01-01", "2025-12-31",
            50.0, 600.0, "monthly", 1, 1,
        ),
    )
    conn.commit()
    policy_id = c.lastrowid
    conn.close()
    return policy_id


@pytest.fixture
def sample_expense():
    """Insert a sample expense budget item and return its id."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO financial_items
           (type, name, monthly_amount, category, frequency, is_fixed_cost, is_policy)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("expense", "Netflix", 15.99, "Subscriptions", "monthly", 0, 0),
    )
    conn.commit()
    item_id = c.lastrowid
    conn.close()
    return item_id


@pytest.fixture
def sample_income():
    """Insert a sample income budget item and return its id."""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO financial_items
           (type, name, monthly_amount, category, frequency, is_fixed_cost, is_policy)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("income", "Salary", 3000.0, "Other", "monthly", 1, 0),
    )
    conn.commit()
    item_id = c.lastrowid
    conn.close()
    return item_id
