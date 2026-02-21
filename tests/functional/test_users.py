"""
Functional tests for user management (admin only) routes:
  GET /users, POST /users/add, GET /users/toggle-admin/<id>,
  GET /users/toggle/<id>, GET /users/delete/<id>
"""
import pytest
from werkzeug.security import generate_password_hash
from app import get_db


def _create_user(email, password="pass123", is_admin=0, enabled=1):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (email, password, is_admin, enabled) VALUES (?,?,?,?)",
        (email, generate_password_hash(password), is_admin, enabled),
    )
    conn.commit()
    uid = c.lastrowid
    conn.close()
    return uid


class TestUsersPage:

    def test_users_page_loads_for_admin(self, auth_client):
        resp = auth_client.get("/users")
        assert resp.status_code == 200

    def test_users_page_shows_admin_user(self, auth_client):
        resp = auth_client.get("/users")
        assert b"admin@policytracker.local" in resp.data

    def test_users_page_blocked_for_regular_user(self, user_client):
        resp = user_client.get("/users", follow_redirects=True)
        assert b"permission" in resp.data.lower()

    def test_users_page_blocked_for_unauthenticated(self, client):
        resp = client.get("/users", follow_redirects=False)
        assert resp.status_code == 302


class TestAddUser:

    def test_add_user_redirects(self, auth_client):
        resp = auth_client.post(
            "/users/add",
            data={"email": "newuser@test.com", "password": "pass123"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_add_user_appears_in_list(self, auth_client):
        auth_client.post(
            "/users/add",
            data={"email": "listed@test.com", "password": "pass123"},
        )
        resp = auth_client.get("/users")
        assert b"listed@test.com" in resp.data

    def test_add_user_stored_in_db(self, auth_client):
        auth_client.post(
            "/users/add",
            data={"email": "stored@test.com", "password": "pass123"},
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email='stored@test.com'")
        row = c.fetchone()
        conn.close()
        assert row is not None

    def test_add_admin_user(self, auth_client):
        auth_client.post(
            "/users/add",
            data={"email": "newadmin@test.com", "password": "pass123", "is_admin": "on"},
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE email='newadmin@test.com'")
        row = c.fetchone()
        conn.close()
        assert row["is_admin"] == 1

    def test_add_duplicate_email_shows_error(self, auth_client):
        auth_client.post("/users/add", data={"email": "dup@test.com", "password": "p1"})
        resp = auth_client.post(
            "/users/add",
            data={"email": "dup@test.com", "password": "p2"},
            follow_redirects=True,
        )
        assert b"already exists" in resp.data.lower()

    def test_add_user_missing_email_shows_error(self, auth_client):
        resp = auth_client.post(
            "/users/add",
            data={"email": "", "password": "pass123"},
            follow_redirects=True,
        )
        assert b"required" in resp.data.lower()

    def test_add_user_missing_password_shows_error(self, auth_client):
        resp = auth_client.post(
            "/users/add",
            data={"email": "nopass@test.com", "password": ""},
            follow_redirects=True,
        )
        assert b"required" in resp.data.lower()


class TestToggleAdmin:

    def test_toggle_admin_on(self, auth_client):
        uid = _create_user("tobeadmin@test.com", is_admin=0)
        auth_client.get(f"/users/toggle-admin/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        conn.close()
        assert row["is_admin"] == 1

    def test_toggle_admin_off(self, auth_client):
        uid = _create_user("demote@test.com", is_admin=1)
        auth_client.get(f"/users/toggle-admin/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        conn.close()
        assert row["is_admin"] == 0


class TestToggleUser:

    def test_toggle_disables_user(self, auth_client):
        uid = _create_user("active@test.com", enabled=1)
        auth_client.get(f"/users/toggle/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT enabled FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        conn.close()
        assert row["enabled"] == 0

    def test_toggle_re_enables_user(self, auth_client):
        uid = _create_user("inactive@test.com", enabled=0)
        auth_client.get(f"/users/toggle/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT enabled FROM users WHERE id=?", (uid,))
        row = c.fetchone()
        conn.close()
        assert row["enabled"] == 1

    def test_cannot_disable_own_account(self, auth_client):
        with auth_client.session_transaction() as sess:
            my_id = sess["user_id"]
        resp = auth_client.get(f"/users/toggle/{my_id}", follow_redirects=True)
        assert b"cannot disable" in resp.data.lower()


class TestDeleteUser:

    def test_delete_user_removes_from_db(self, auth_client):
        uid = _create_user("todelete@test.com")
        auth_client.get(f"/users/delete/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE id=?", (uid,))
        assert c.fetchone() is None
        conn.close()

    def test_cannot_delete_own_account(self, auth_client):
        with auth_client.session_transaction() as sess:
            my_id = sess["user_id"]
        resp = auth_client.get(f"/users/delete/{my_id}", follow_redirects=True)
        assert b"cannot delete" in resp.data.lower()

    def test_cannot_delete_last_admin(self, auth_client):
        """The seeded admin@policytracker.local is the only admin; deleting should fail."""
        with auth_client.session_transaction() as sess:
            admin_id = sess["user_id"]
        # Add a second admin so we can test the 'last admin' guard on the first
        second_admin_id = _create_user("second@test.com", is_admin=1)

        # Delete the second admin first, leaving only the first
        auth_client.get(f"/users/delete/{second_admin_id}")

        # Now attempt to delete the last remaining admin (ourselves — should fail with different message)
        resp = auth_client.get(f"/users/delete/{admin_id}", follow_redirects=True)
        # Either "cannot delete your own" or "cannot delete last admin" error
        assert b"cannot" in resp.data.lower()

    def test_delete_redirects(self, auth_client):
        uid = _create_user("redirect@test.com")
        resp = auth_client.get(f"/users/delete/{uid}", follow_redirects=False)
        assert resp.status_code == 302
