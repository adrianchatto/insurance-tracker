"""
Functional tests for authentication routes:
  GET/POST /login, GET /logout, login_required redirect, disabled account.
"""
import pytest
from werkzeug.security import generate_password_hash
from app import get_db


class TestLogin:

    def test_login_page_loads(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"login" in resp.data.lower()

    def test_valid_admin_login_redirects(self, client):
        resp = client.post(
            "/login",
            data={"email": "admin@policytracker.local", "password": "admin"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/policies" in resp.headers["Location"]

    def test_valid_login_sets_session(self, client):
        with client.session_transaction() as sess:
            assert "user_id" not in sess
        client.post(
            "/login",
            data={"email": "admin@policytracker.local", "password": "admin"},
        )
        with client.session_transaction() as sess:
            assert "user_id" in sess
            assert sess["email"] == "admin@policytracker.local"
            assert sess["is_admin"] == 1

    def test_invalid_password_shows_error(self, client):
        resp = client.post(
            "/login",
            data={"email": "admin@policytracker.local", "password": "wrongpass"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid email or password" in resp.data

    def test_unknown_email_shows_error(self, client):
        resp = client.post(
            "/login",
            data={"email": "nobody@example.com", "password": "pass"},
            follow_redirects=True,
        )
        assert b"Invalid email or password" in resp.data

    def test_disabled_account_cannot_login(self, client):
        conn = get_db()
        c = conn.cursor()
        hashed = generate_password_hash("pass123")
        c.execute(
            "INSERT INTO users (email, password, is_admin, enabled) VALUES (?,?,?,?)",
            ("disabled@example.com", hashed, 0, 0),
        )
        conn.commit()
        conn.close()

        resp = client.post(
            "/login",
            data={"email": "disabled@example.com", "password": "pass123"},
            follow_redirects=True,
        )
        assert b"disabled" in resp.data.lower()
        with client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_empty_credentials_shows_error(self, client):
        resp = client.post(
            "/login",
            data={"email": "", "password": ""},
            follow_redirects=True,
        )
        assert b"Invalid email or password" in resp.data


class TestLogout:

    def test_logout_clears_session(self, auth_client):
        with auth_client.session_transaction() as sess:
            assert "user_id" in sess

        auth_client.get("/logout")

        with auth_client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_logout_redirects_to_login(self, auth_client):
        resp = auth_client.get("/logout", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


class TestLoginRequired:

    def test_unauthenticated_policies_redirects_to_login(self, client):
        resp = client.get("/policies", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_unauthenticated_budget_redirects(self, client):
        resp = client.get("/budget", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_unauthenticated_calendar_redirects(self, client):
        resp = client.get("/calendar", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_unauthenticated_add_policy_redirects(self, client):
        resp = client.post("/add", data={}, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_disabled_user_mid_session_is_rejected(self, client, regular_user):
        """A user who gets disabled while logged in should be bounced."""
        client.post(
            "/login",
            data={"email": regular_user["email"], "password": regular_user["password"]},
        )
        # Admin disables the user
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET enabled=0 WHERE id=?", (regular_user["id"],))
        conn.commit()
        conn.close()

        resp = client.get("/policies", follow_redirects=True)
        assert b"disabled" in resp.data.lower()


class TestAdminRequired:

    def test_non_admin_cannot_access_settings(self, user_client):
        resp = user_client.get("/settings", follow_redirects=True)
        assert b"permission" in resp.data.lower() or resp.status_code in (302, 403)

    def test_non_admin_cannot_access_users(self, user_client):
        resp = user_client.get("/users", follow_redirects=True)
        assert b"permission" in resp.data.lower() or resp.status_code in (302, 403)

    def test_admin_can_access_settings(self, auth_client):
        resp = auth_client.get("/settings")
        assert resp.status_code == 200

    def test_admin_can_access_users(self, auth_client):
        resp = auth_client.get("/users")
        assert resp.status_code == 200
