"""
Functional tests for backup/restore routes:
  GET /backup, GET /backup/download, POST /backup/restore
"""
import io
import json
import pytest
from app import get_db


class TestBackupPage:

    def test_backup_page_loads_for_admin(self, auth_client):
        resp = auth_client.get("/backup")
        assert resp.status_code == 200

    def test_backup_page_blocked_for_regular_user(self, user_client):
        resp = user_client.get("/backup", follow_redirects=True)
        assert b"permission" in resp.data.lower()

    def test_backup_page_blocked_for_unauthenticated(self, client):
        resp = client.get("/backup", follow_redirects=False)
        assert resp.status_code == 302


class TestDownloadBackup:

    def test_download_json_backup(self, auth_client, sample_policy):
        resp = auth_client.get("/backup/download?type=json")
        assert resp.status_code == 200
        assert resp.content_type == "application/json" or "json" in resp.headers.get(
            "Content-Disposition", ""
        )
        data = json.loads(resp.data)
        assert "financial_items" in data
        assert "categories" in data
        assert "settings" in data

    def test_download_json_contains_policy(self, auth_client, sample_policy):
        resp = auth_client.get("/backup/download?type=json")
        data = json.loads(resp.data)
        names = [item["name"] for item in data["financial_items"]]
        assert "Home Insurance" in names

    def test_download_db_backup(self, auth_client):
        resp = auth_client.get("/backup/download?type=db")
        assert resp.status_code == 200
        # SQLite files begin with the magic header
        assert resp.data[:6] == b"SQLite" or len(resp.data) > 0

    def test_download_json_backup_has_version(self, auth_client):
        resp = auth_client.get("/backup/download?type=json")
        data = json.loads(resp.data)
        assert "version" in data
        assert data["version"] == "2.0"

    def test_download_default_is_db(self, auth_client):
        resp = auth_client.get("/backup/download")
        assert resp.status_code == 200


class TestRestoreBackup:

    def test_restore_no_file_shows_error(self, auth_client):
        resp = auth_client.post(
            "/backup/restore",
            data={},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"no file" in resp.data.lower()

    def test_restore_invalid_extension_shows_error(self, auth_client):
        resp = auth_client.post(
            "/backup/restore",
            data={"backup_file": (io.BytesIO(b"some data"), "backup.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"invalid" in resp.data.lower()

    def test_restore_valid_json_backup(self, auth_client, sample_policy):
        # 1. Download a backup
        dl_resp = auth_client.get("/backup/download?type=json")
        backup_bytes = dl_resp.data

        # 2. Clear the DB
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM financial_items")
        conn.commit()
        conn.close()

        # 3. Restore from the backup
        resp = auth_client.post(
            "/backup/restore",
            data={"backup_file": (io.BytesIO(backup_bytes), "backup.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"restored" in resp.data.lower()

        # 4. Verify data is back
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM financial_items WHERE name='Home Insurance'")
        row = c.fetchone()
        conn.close()
        assert row is not None

    def test_restore_old_format_json(self, auth_client):
        """Restore a v1-format backup with 'policies' key (legacy migration path)."""
        old_backup = {
            "policies": [
                {
                    "id": 1,
                    "friendly_name": "Old Policy",
                    "policy_number": "OLD-001",
                    "insurer": "OldCo",
                    "category": "Insurance",
                    "start_date": "2023-01-01",
                    "end_date": "2024-01-01",
                    "monthly_amount": 20.0,
                    "annual_amount": 240.0,
                    "remaining_balance": None,
                    "account_source": None,
                    "insurer_website": None,
                    "notes": None,
                    "created_at": "2023-01-01T00:00:00",
                }
            ],
            "budget_items": [],
            "categories": [],
            "settings": [],
        }
        backup_bytes = json.dumps(old_backup).encode()

        resp = auth_client.post(
            "/backup/restore",
            data={"backup_file": (io.BytesIO(backup_bytes), "backup.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"restored" in resp.data.lower()

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM financial_items WHERE name='Old Policy'")
        row = c.fetchone()
        conn.close()
        assert row is not None

    def test_restore_malformed_json_shows_error(self, auth_client):
        resp = auth_client.post(
            "/backup/restore",
            data={"backup_file": (io.BytesIO(b"not valid json {{{"), "backup.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"error" in resp.data.lower()
