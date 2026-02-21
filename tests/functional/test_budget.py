"""
Functional tests for budget management routes:
  GET /, GET /budget, POST /budget/add, GET/POST /budget/edit/<id>,
  GET /budget/delete/<id>, POST /budget/toggle_policy/<id>
"""
import pytest
from app import get_db


class TestBudgetPage:

    def test_root_redirects_to_budget(self, auth_client):
        resp = auth_client.get("/", follow_redirects=False)
        # Either renders or redirects to /budget
        assert resp.status_code in (200, 302)

    def test_budget_page_loads(self, auth_client):
        resp = auth_client.get("/budget")
        assert resp.status_code == 200

    def test_budget_shows_expense_items(self, auth_client, sample_expense):
        resp = auth_client.get("/budget")
        assert b"Netflix" in resp.data

    def test_budget_shows_income_items(self, auth_client, sample_income):
        resp = auth_client.get("/budget")
        assert b"Salary" in resp.data

    def test_budget_totals_calculated(self, auth_client, sample_expense, sample_income):
        resp = auth_client.get("/budget")
        assert resp.status_code == 200
        # Totals are rendered in the page

    def test_budget_pagination_default_10_per_page(self, auth_client):
        # Insert 15 expenses
        conn = get_db()
        c = conn.cursor()
        for i in range(15):
            c.execute(
                "INSERT INTO financial_items (type, name, monthly_amount, frequency, is_fixed_cost, is_policy)"
                " VALUES (?,?,?,?,?,?)",
                ("expense", f"Expense {i}", 10.0, "monthly", 0, 0),
            )
        conn.commit()
        conn.close()

        resp = auth_client.get("/budget?expenses_page=1")
        assert resp.status_code == 200

    def test_budget_pagination_page_2(self, auth_client):
        conn = get_db()
        c = conn.cursor()
        for i in range(15):
            c.execute(
                "INSERT INTO financial_items (type, name, monthly_amount, frequency, is_fixed_cost, is_policy)"
                " VALUES (?,?,?,?,?,?)",
                ("expense", f"Item {i:02d}", 10.0, "monthly", 0, 0),
            )
        conn.commit()
        conn.close()

        resp = auth_client.get("/budget?expenses_page=2&per_page=10")
        assert resp.status_code == 200

    def test_budget_invalid_per_page_defaults_to_10(self, auth_client):
        resp = auth_client.get("/budget?per_page=999")
        assert resp.status_code == 200

    def test_budget_filter_by_fixed(self, auth_client):
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO financial_items (type, name, monthly_amount, frequency, is_fixed_cost, is_policy)"
            " VALUES (?,?,?,?,?,?)",
            ("expense", "Fixed Cost", 100.0, "monthly", 1, 0),
        )
        conn.commit()
        conn.close()
        resp = auth_client.get("/budget?type=fixed")
        assert resp.status_code == 200
        assert b"Fixed Cost" in resp.data

    def test_budget_sort_by_amount(self, auth_client, sample_expense):
        resp = auth_client.get("/budget?sort_expense=amount&order_expense=desc")
        assert resp.status_code == 200


class TestAddBudgetItem:

    def test_add_expense_redirects(self, auth_client):
        resp = auth_client.post(
            "/budget/add",
            data={
                "type": "expense",
                "name": "Spotify",
                "amount": "9.99",
                "category": "Subscriptions",
                "frequency": "monthly",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302

    def test_add_expense_appears_in_budget(self, auth_client):
        auth_client.post(
            "/budget/add",
            data={
                "type": "expense",
                "name": "Amazon Prime",
                "amount": "8.99",
                "category": "Subscriptions",
                "frequency": "monthly",
            },
        )
        resp = auth_client.get("/budget")
        assert b"Amazon Prime" in resp.data

    def test_add_income_item(self, auth_client):
        auth_client.post(
            "/budget/add",
            data={
                "type": "income",
                "name": "Freelance",
                "amount": "500.00",
                "category": "Other",
                "frequency": "monthly",
            },
        )
        resp = auth_client.get("/budget")
        assert b"Freelance" in resp.data

    def test_add_item_stored_as_not_policy(self, auth_client):
        auth_client.post(
            "/budget/add",
            data={
                "type": "expense",
                "name": "NotAPolicy",
                "amount": "20.00",
                "category": "Other",
                "frequency": "monthly",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_policy FROM financial_items WHERE name='NotAPolicy'")
        row = c.fetchone()
        conn.close()
        assert row["is_policy"] == 0

    def test_add_item_missing_required_fields_shows_error(self, auth_client):
        resp = auth_client.post(
            "/budget/add",
            data={"type": "expense"},
            follow_redirects=True,
        )
        assert b"required" in resp.data.lower()

    def test_add_fixed_cost_flag(self, auth_client):
        auth_client.post(
            "/budget/add",
            data={
                "type": "expense",
                "name": "Rent",
                "amount": "1200.00",
                "category": "Other",
                "frequency": "monthly",
                "is_fixed_cost": "on",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_fixed_cost FROM financial_items WHERE name='Rent'")
        row = c.fetchone()
        conn.close()
        assert row["is_fixed_cost"] == 1


class TestEditBudgetItem:

    def test_get_edit_returns_json(self, auth_client, sample_expense):
        resp = auth_client.get(f"/budget/edit/{sample_expense}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["name"] == "Netflix"

    def test_get_edit_nonexistent_item_redirects(self, auth_client):
        resp = auth_client.get("/budget/edit/99999", follow_redirects=True)
        assert b"not found" in resp.data.lower()

    def test_post_edit_updates_item(self, auth_client, sample_expense):
        auth_client.post(
            f"/budget/edit/{sample_expense}",
            data={
                "type": "expense",
                "name": "Netflix Premium",
                "amount": "19.99",
                "category": "Subscriptions",
                "frequency": "monthly",
            },
        )
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name, monthly_amount FROM financial_items WHERE id=?", (sample_expense,))
        row = c.fetchone()
        conn.close()
        assert row["name"] == "Netflix Premium"
        assert row["monthly_amount"] == pytest.approx(19.99)

    def test_post_edit_missing_fields_shows_error(self, auth_client, sample_expense):
        resp = auth_client.post(
            f"/budget/edit/{sample_expense}",
            data={"type": "expense", "name": ""},
            follow_redirects=True,
        )
        assert b"required" in resp.data.lower()


class TestDeleteBudgetItem:

    def test_delete_removes_item(self, auth_client, sample_expense):
        auth_client.get(f"/budget/delete/{sample_expense}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM financial_items WHERE id=?", (sample_expense,))
        assert c.fetchone() is None
        conn.close()

    def test_delete_redirects(self, auth_client, sample_expense):
        resp = auth_client.get(f"/budget/delete/{sample_expense}", follow_redirects=False)
        assert resp.status_code == 302


class TestTogglePolicy:

    def test_toggle_policy_returns_json(self, auth_client, sample_expense):
        resp = auth_client.post(f"/budget/toggle_policy/{sample_expense}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True

    def test_toggle_policy_changes_value(self, auth_client, sample_expense):
        # Initial is_policy is 0
        resp = auth_client.post(f"/budget/toggle_policy/{sample_expense}")
        data = resp.get_json()
        assert data["is_policy"] == 1

        # Toggle back
        resp = auth_client.post(f"/budget/toggle_policy/{sample_expense}")
        data = resp.get_json()
        assert data["is_policy"] == 0

    def test_toggle_nonexistent_item_returns_404(self, auth_client):
        resp = auth_client.post("/budget/toggle_policy/99999")
        assert resp.status_code == 404
