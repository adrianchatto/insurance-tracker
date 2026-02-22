"""
Functional tests for policy management routes:
  GET /policies, POST /add, GET/POST /edit/<id>, GET /delete/<id>
"""
import pytest
from app import get_db


def _insert_policies(n, start=1):
    """Helper: bulk-insert n policies into the DB."""
    conn = get_db()
    c = conn.cursor()
    for i in range(start, start + n):
        c.execute(
            """INSERT INTO financial_items
               (type, name, policy_number, insurer, category, start_date, end_date,
                monthly_amount, annual_amount, frequency, is_fixed_cost, is_policy)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("expense", f"Policy {i:03d}", f"P-{i:03d}", "TestCo",
             "Insurance", "2024-01-01", "2025-12-31",
             10.0, 120.0, "monthly", 1, 1),
        )
    conn.commit()
    conn.close()


class TestPoliciesListPage:

    def test_policies_page_loads(self, auth_client):
        resp = auth_client.get("/policies")
        assert resp.status_code == 200

    def test_policies_page_shows_policy_entries(self, auth_client, sample_policy):
        resp = auth_client.get("/policies")
        assert b"Home Insurance" in resp.data
        assert b"POL-001" in resp.data
        assert b"Acme Insurers" in resp.data

    def test_empty_policies_page_still_loads(self, auth_client):
        resp = auth_client.get("/policies")
        assert resp.status_code == 200

    def test_policies_sort_by_name(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?sort=name&order=asc")
        assert resp.status_code == 200

    def test_policies_sort_by_end_date(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?sort=end_date&order=desc")
        assert resp.status_code == 200

    def test_policies_filter_by_category(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?category=Insurance")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data

    def test_policies_filter_by_nonexistent_category_returns_empty(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?category=NonExistentCat")
        assert resp.status_code == 200
        assert b"Home Insurance" not in resp.data

    def test_policies_filter_by_provider(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?provider=Acme+Insurers")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data

    def test_policies_expiry_filter_soon(self, auth_client):
        """Insert a policy expiring in 5 days and filter for 'soon'."""
        from datetime import datetime, timedelta
        soon = (datetime.now() + timedelta(days=5)).strftime("%Y-%m-%d")
        conn = get_db()
        c = conn.cursor()
        c.execute(
            """INSERT INTO financial_items
               (type, name, policy_number, insurer, category, start_date, end_date,
                monthly_amount, frequency, is_fixed_cost, is_policy)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ("expense", "Expiring Soon", "P-SOON", "SoonInsurer", "Insurance",
             "2024-01-01", soon, 10.0, "monthly", 1, 1),
        )
        conn.commit()
        conn.close()

        resp = auth_client.get("/policies?expiry=soon")
        assert b"Expiring Soon" in resp.data

    def test_policies_amount_filter_under100(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?amount_range=under100")
        assert resp.status_code == 200
        assert b"Home Insurance" in resp.data  # monthly=50 < 100

    def test_policies_amount_filter_over1000(self, auth_client, sample_policy):
        resp = auth_client.get("/policies?amount_range=over1000")
        assert resp.status_code == 200
        assert b"Home Insurance" not in resp.data  # 50 is not > 1000

    def test_invalid_sort_param_does_not_crash(self, auth_client):
        resp = auth_client.get("/policies?sort=DROPTABLE&order=INVALID")
        assert resp.status_code == 200


class TestAddPolicy:

    def test_add_valid_policy_redirects(self, auth_client):
        resp = auth_client.post(
            "/add",
            data={
                "friendly_name": "Car Insurance",
                "policy_number": "CAR-001",
                "insurer": "Safe Drive",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-01-01",
                "monthly_amount": "75.00",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_add_policy_appears_in_list(self, auth_client):
        auth_client.post(
            "/add",
            data={
                "friendly_name": "Life Insurance",
                "policy_number": "LIFE-001",
                "insurer": "LifeCo",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2030-12-31",
                "monthly_amount": "30.00",
            },
        )
        resp = auth_client.get("/policies")
        assert b"Life Insurance" in resp.data
        assert b"LIFE-001" in resp.data
        assert b"LifeCo" in resp.data

    def test_add_policy_calculates_annual_from_monthly(self, auth_client):
        auth_client.post(
            "/add",
            data={
                "friendly_name": "Calc Test",
                "policy_number": "CALC-001",
                "insurer": "TestCo",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "monthly_amount": "100.00",
                "annual_amount": "",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT annual_amount FROM financial_items WHERE name='Calc Test'")
        row = c.fetchone()
        conn.close()
        assert row["annual_amount"] == 1200.0

    def test_add_policy_calculates_monthly_from_annual(self, auth_client):
        auth_client.post(
            "/add",
            data={
                "friendly_name": "Annual Test",
                "policy_number": "ANN-001",
                "insurer": "TestCo",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "monthly_amount": "",
                "annual_amount": "1200.00",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT monthly_amount FROM financial_items WHERE name='Annual Test'")
        row = c.fetchone()
        conn.close()
        assert row["monthly_amount"] == pytest.approx(100.0)

    def test_add_policy_missing_required_fields_shows_error(self, auth_client):
        resp = auth_client.post(
            "/add",
            data={"friendly_name": "Incomplete"},
            follow_redirects=True,
        )
        assert b"required" in resp.data.lower()

    def test_add_policy_is_stored_as_policy(self, auth_client):
        auth_client.post(
            "/add",
            data={
                "friendly_name": "Policy Check",
                "policy_number": "PC-001",
                "insurer": "PCo",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "monthly_amount": "50.00",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_policy FROM financial_items WHERE name='Policy Check'")
        row = c.fetchone()
        conn.close()
        assert row["is_policy"] == 1


class TestEditPolicy:

    def test_edit_page_loads(self, auth_client, sample_policy):
        resp = auth_client.get(f"/edit/{sample_policy}")
        assert resp.status_code == 200
        # Name is pre-populated in the edit form (the fix for issue #2)
        assert b"Home Insurance" in resp.data
        assert b"POL-001" in resp.data

    def test_edit_nonexistent_policy_redirects(self, auth_client):
        resp = auth_client.get("/edit/99999", follow_redirects=True)
        assert b"not found" in resp.data.lower()

    def test_edit_policy_updates_name(self, auth_client, sample_policy):
        auth_client.post(
            f"/edit/{sample_policy}",
            data={
                "friendly_name": "Updated Home Insurance",
                "policy_number": "POL-001",
                "insurer": "Acme Insurers",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "monthly_amount": "50.00",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM financial_items WHERE id=?", (sample_policy,))
        row = c.fetchone()
        conn.close()
        assert row["name"] == "Updated Home Insurance"

    def test_edit_policy_missing_fields_shows_error(self, auth_client, sample_policy):
        resp = auth_client.post(
            f"/edit/{sample_policy}",
            data={"friendly_name": ""},
            follow_redirects=True,
        )
        assert b"required" in resp.data.lower()


class TestDeletePolicy:

    def test_delete_policy_removes_from_db(self, auth_client, sample_policy):
        auth_client.get(f"/delete/{sample_policy}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM financial_items WHERE id=?", (sample_policy,))
        row = c.fetchone()
        conn.close()
        assert row is None

    def test_delete_policy_redirects(self, auth_client, sample_policy):
        resp = auth_client.get(f"/delete/{sample_policy}", follow_redirects=False)
        assert resp.status_code == 302

    def test_delete_nonexistent_policy_does_not_crash(self, auth_client):
        resp = auth_client.get("/delete/99999")
        assert resp.status_code in (200, 302)


class TestPoliciesPagination:

    def test_default_per_page_is_10(self, auth_client):
        _insert_policies(15)
        resp = auth_client.get("/policies")
        assert resp.status_code == 200
        # Only 10 of 15 policies should appear on page 1
        assert b"Policy 001" in resp.data
        assert b"Policy 011" not in resp.data

    def test_page_2_shows_remaining_items(self, auth_client):
        _insert_policies(15)
        resp = auth_client.get("/policies?page=2")
        assert resp.status_code == 200
        assert b"Policy 011" in resp.data

    def test_per_page_25_shows_all_when_under_25(self, auth_client):
        _insert_policies(15)
        resp = auth_client.get("/policies?per_page=25")
        assert resp.status_code == 200
        assert b"Policy 001" in resp.data
        assert b"Policy 015" in resp.data

    def test_invalid_per_page_defaults_to_10(self, auth_client):
        _insert_policies(15)
        resp = auth_client.get("/policies?per_page=999")
        assert resp.status_code == 200
        # Defaults to 10 — page 1 has items 1-10 only
        assert b"Policy 001" in resp.data
        assert b"Policy 011" not in resp.data

    def test_pagination_controls_appear_when_multiple_pages(self, auth_client):
        _insert_policies(15)
        resp = auth_client.get("/policies")
        assert b"Next" in resp.data

    def test_no_pagination_controls_when_single_page(self, auth_client):
        _insert_policies(5)
        resp = auth_client.get("/policies")
        assert b"Next" not in resp.data
        assert b"Previous" not in resp.data

    def test_totals_reflect_all_items_not_just_page(self, auth_client):
        _insert_policies(15)  # 15 x $10/month = $150 total
        resp = auth_client.get("/policies?page=1&per_page=10")
        assert b"$150.00" in resp.data  # total across all pages

    def test_pagination_preserved_with_filters(self, auth_client):
        _insert_policies(15)
        resp = auth_client.get("/policies?category=Insurance&page=2")
        assert resp.status_code == 200

    def test_out_of_range_page_clamps_to_last(self, auth_client):
        _insert_policies(5)
        resp = auth_client.get("/policies?page=999")
        assert resp.status_code == 200
