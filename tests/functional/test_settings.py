"""
Functional tests for settings management routes:
  GET/POST /settings
"""
import pytest
from app import get_db, get_setting


class TestSettingsPage:

    def test_settings_page_loads_for_admin(self, auth_client):
        resp = auth_client.get("/settings")
        assert resp.status_code == 200

    def test_settings_page_blocked_for_regular_user(self, user_client):
        resp = user_client.get("/settings", follow_redirects=True)
        assert b"permission" in resp.data.lower() or resp.status_code in (302, 403)

    def test_settings_page_blocked_for_unauthenticated(self, client):
        resp = client.get("/settings", follow_redirects=False)
        assert resp.status_code == 302

    def test_settings_displays_current_values(self, auth_client):
        resp = auth_client.get("/settings")
        assert b"30" in resp.data  # default notification_days


class TestUpdateSettings:

    def test_update_notification_days(self, auth_client):
        auth_client.post(
            "/settings",
            data={
                "notification_days": "60",
                "notification_enabled": "on",
                "smtp_port": "587",
                "currency_symbol": "$",
                "currency_code": "USD",
            },
        )
        from app import app
        with app.app_context():
            value = get_setting("notification_days")
        assert value == "60"

    def test_update_currency_symbol(self, auth_client):
        auth_client.post(
            "/settings",
            data={
                "notification_days": "30",
                "smtp_port": "587",
                "currency_symbol": "£",
                "currency_code": "GBP",
            },
        )
        from app import app
        with app.app_context():
            symbol = get_setting("currency_symbol")
        assert symbol == "£"

    def test_settings_update_redirects(self, auth_client):
        resp = auth_client.post(
            "/settings",
            data={
                "notification_days": "30",
                "smtp_port": "587",
                "currency_symbol": "$",
                "currency_code": "USD",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_notification_enabled_true(self, auth_client):
        auth_client.post(
            "/settings",
            data={
                "notification_days": "30",
                "notification_enabled": "on",
                "smtp_port": "587",
                "currency_symbol": "$",
                "currency_code": "USD",
            },
        )
        from app import app
        with app.app_context():
            value = get_setting("notification_enabled")
        assert value == "true"

    def test_notification_enabled_false_when_unchecked(self, auth_client):
        # Not including notification_enabled in form = unchecked = false
        auth_client.post(
            "/settings",
            data={
                "notification_days": "30",
                "smtp_port": "587",
                "currency_symbol": "$",
                "currency_code": "USD",
            },
        )
        from app import app
        with app.app_context():
            value = get_setting("notification_enabled")
        assert value == "false"

    def test_smtp_password_not_overwritten_when_blank(self, auth_client):
        """If smtp_password field is empty, existing password should not be erased."""
        from app import set_setting, app
        with app.app_context():
            set_setting("smtp_password", "secret123")

        auth_client.post(
            "/settings",
            data={
                "notification_days": "30",
                "smtp_port": "587",
                "smtp_password": "",  # blank = don't overwrite
                "currency_symbol": "$",
                "currency_code": "USD",
            },
        )
        with app.app_context():
            pw = get_setting("smtp_password")
        assert pw == "secret123"
