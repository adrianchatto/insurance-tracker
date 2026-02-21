"""
Functional tests for category management routes:
  GET/POST /categories, GET /categories/delete/<id>
"""
import pytest
from app import get_db


class TestCategoriesPage:

    def test_categories_page_loads(self, auth_client):
        resp = auth_client.get("/categories")
        assert resp.status_code == 200

    def test_default_categories_are_shown(self, auth_client):
        resp = auth_client.get("/categories")
        assert b"Insurance" in resp.data
        assert b"Mortgage" in resp.data

    def test_unauthenticated_user_is_redirected(self, client):
        resp = client.get("/categories", follow_redirects=False)
        assert resp.status_code == 302


class TestAddCategory:

    def test_add_category_redirects(self, auth_client):
        resp = auth_client.post(
            "/categories",
            data={"category_name": "Investments"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_add_category_appears_in_list(self, auth_client):
        auth_client.post("/categories", data={"category_name": "Investments"})
        resp = auth_client.get("/categories")
        assert b"Investments" in resp.data

    def test_add_category_persisted_in_db(self, auth_client):
        auth_client.post("/categories", data={"category_name": "TestCat"})
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM categories WHERE name='TestCat'")
        row = c.fetchone()
        conn.close()
        assert row is not None

    def test_add_duplicate_category_shows_error(self, auth_client):
        auth_client.post("/categories", data={"category_name": "Insurance"})
        resp = auth_client.post(
            "/categories",
            data={"category_name": "Insurance"},
            follow_redirects=True,
        )
        assert b"already exists" in resp.data.lower()

    def test_add_empty_category_name_is_ignored(self, auth_client):
        resp = auth_client.post(
            "/categories",
            data={"category_name": ""},
            follow_redirects=False,
        )
        # Should redirect without adding
        assert resp.status_code == 302


class TestDeleteCategory:

    def test_delete_category_removes_it(self, auth_client):
        # Add a custom category first
        auth_client.post("/categories", data={"category_name": "ToDelete"})
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM categories WHERE name='ToDelete'")
        row = c.fetchone()
        cat_id = row["id"]
        conn.close()

        auth_client.get(f"/categories/delete/{cat_id}")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM categories WHERE name='ToDelete'")
        assert c.fetchone() is None
        conn.close()

    def test_delete_category_redirects(self, auth_client):
        auth_client.post("/categories", data={"category_name": "TempCat"})
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM categories WHERE name='TempCat'")
        row = c.fetchone()
        conn.close()

        resp = auth_client.get(f"/categories/delete/{row['id']}", follow_redirects=False)
        assert resp.status_code == 302
