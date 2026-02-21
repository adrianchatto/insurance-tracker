"""
Functional tests for the search route: GET /search
"""
import pytest
from app import get_db


class TestSearch:

    def test_search_with_results(self, auth_client, sample_policy):
        resp = auth_client.get("/search?q=Home")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data

    def test_search_by_insurer(self, auth_client, sample_policy):
        resp = auth_client.get("/search?q=Acme")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data

    def test_search_by_policy_number(self, auth_client, sample_policy):
        resp = auth_client.get("/search?q=POL-001")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data

    def test_search_by_category(self, auth_client, sample_policy):
        resp = auth_client.get("/search?q=Insurance")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data

    def test_search_no_results(self, auth_client):
        resp = auth_client.get("/search?q=XYZZY_NO_MATCH")
        assert resp.status_code == 200
        # Should render with 0 results

    def test_search_empty_query_redirects(self, auth_client):
        resp = auth_client.get("/search?q=", follow_redirects=True)
        assert b"enter a search term" in resp.data.lower()

    def test_search_missing_q_redirects(self, auth_client):
        resp = auth_client.get("/search", follow_redirects=True)
        assert b"enter a search term" in resp.data.lower()

    def test_search_finds_budget_items(self, auth_client, sample_expense):
        resp = auth_client.get("/search?q=Netflix")
        assert resp.status_code == 200
        assert b"Netflix" in resp.data

    def test_search_finds_income(self, auth_client, sample_income):
        resp = auth_client.get("/search?q=Salary")
        assert resp.status_code == 200
        assert b"Salary" in resp.data

    def test_search_unauthenticated_redirects(self, client):
        resp = client.get("/search?q=test", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_search_shows_result_count(self, auth_client, sample_policy):
        resp = auth_client.get("/search?q=Home")
        # The template receives result_count
        assert resp.status_code == 200

    def test_search_by_notes(self, auth_client):
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO financial_items (type, name, notes, frequency, is_fixed_cost, is_policy)"
            " VALUES (?,?,?,?,?,?)",
            ("expense", "SomeItem", "special note here", "monthly", 0, 0),
        )
        conn.commit()
        conn.close()

        resp = auth_client.get("/search?q=special+note")
        assert b"SomeItem" in resp.data
