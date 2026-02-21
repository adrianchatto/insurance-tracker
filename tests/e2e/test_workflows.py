"""
End-to-end workflow tests using the Flask test client.
Each test simulates a complete user journey across multiple routes.
"""
import io
import json
import pytest
from app import get_db


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def login(client, email="admin@policytracker.local", password="admin"):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=True,
    )


def logout(client):
    return client.get("/logout", follow_redirects=True)


# ---------------------------------------------------------------------------
# Policy lifecycle workflow
# ---------------------------------------------------------------------------

class TestPolicyLifecycleWorkflow:
    """
    Full lifecycle: login → add policy → view in list → edit → verify update
    → delete → confirm removed.
    """

    def test_full_policy_lifecycle(self, client):
        # Step 1: Login
        resp = login(client)
        assert b"Logged in" in resp.data or resp.status_code == 200

        # Step 2: Add a policy
        resp = client.post(
            "/add",
            data={
                "friendly_name": "E2E Home Policy",
                "policy_number": "E2E-001",
                "insurer": "E2E Insurer Co",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "monthly_amount": "55.00",
            },
            follow_redirects=True,
        )
        assert b"added successfully" in resp.data.lower()

        # Step 3: Policy appears in list
        resp = client.get("/policies")
        assert b"E2E Home Policy" in resp.data
        assert b"E2E-001" in resp.data
        assert b"E2E Insurer Co" in resp.data

        # Step 4: Get the policy ID from DB
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM financial_items WHERE name='E2E Home Policy'")
        policy_id = c.fetchone()["id"]
        conn.close()

        # Step 5: Edit the policy (change insurer to verify the edit worked)
        resp = client.post(
            f"/edit/{policy_id}",
            data={
                "friendly_name": "E2E Home Policy (Updated)",
                "policy_number": "E2E-001",
                "insurer": "E2E Insurer Co Updated",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2026-12-31",
                "monthly_amount": "60.00",
            },
            follow_redirects=True,
        )
        assert b"updated successfully" in resp.data.lower()

        # Step 6: Updated name and insurer appear in list
        resp = client.get("/policies")
        assert b"E2E Home Policy (Updated)" in resp.data
        assert b"E2E Insurer Co Updated" in resp.data

        # Verify the name was updated in the DB
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM financial_items WHERE id=?", (policy_id,))
        assert c.fetchone()["name"] == "E2E Home Policy (Updated)"
        conn.close()

        # Step 7: Delete the policy
        resp = client.get(f"/delete/{policy_id}", follow_redirects=True)
        assert b"deleted successfully" in resp.data.lower()

        # Step 8: Policy is gone from DB
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM financial_items WHERE id=?", (policy_id,))
        assert c.fetchone() is None
        conn.close()

        # Step 9: Logout
        resp = logout(client)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Budget management workflow
# ---------------------------------------------------------------------------

class TestBudgetManagementWorkflow:
    """
    Workflow: login → add income → add expense → verify totals exist on page
    → edit expense → delete both items → confirm page still loads.
    """

    def test_full_budget_workflow(self, client):
        login(client)

        # Add income
        resp = client.post(
            "/budget/add",
            data={
                "type": "income",
                "name": "E2E Salary",
                "amount": "3000.00",
                "category": "Other",
                "frequency": "monthly",
            },
            follow_redirects=True,
        )
        assert b"added successfully" in resp.data.lower()

        # Add expense
        resp = client.post(
            "/budget/add",
            data={
                "type": "expense",
                "name": "E2E Rent",
                "amount": "1000.00",
                "category": "Other",
                "frequency": "monthly",
                "is_fixed_cost": "on",
            },
            follow_redirects=True,
        )
        assert b"added successfully" in resp.data.lower()

        # Both appear on budget page
        resp = client.get("/budget")
        assert b"E2E Salary" in resp.data
        assert b"E2E Rent" in resp.data

        # Get IDs
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM financial_items WHERE name='E2E Salary'")
        income_id = c.fetchone()["id"]
        c.execute("SELECT id FROM financial_items WHERE name='E2E Rent'")
        expense_id = c.fetchone()["id"]
        conn.close()

        # Edit expense
        resp = client.post(
            f"/budget/edit/{expense_id}",
            data={
                "type": "expense",
                "name": "E2E Rent (Updated)",
                "amount": "1100.00",
                "category": "Other",
                "frequency": "monthly",
                "is_fixed_cost": "on",
            },
            follow_redirects=True,
        )
        assert b"updated successfully" in resp.data.lower()

        # Delete both
        client.get(f"/budget/delete/{income_id}", follow_redirects=True)
        client.get(f"/budget/delete/{expense_id}", follow_redirects=True)

        resp = client.get("/budget")
        assert b"E2E Salary" not in resp.data
        assert b"E2E Rent" not in resp.data

        logout(client)


# ---------------------------------------------------------------------------
# Category management workflow
# ---------------------------------------------------------------------------

class TestCategoryManagementWorkflow:

    def test_add_use_and_delete_category(self, client):
        login(client)

        # Add a custom category
        resp = client.post(
            "/categories",
            data={"category_name": "E2E Investments"},
            follow_redirects=True,
        )
        assert b"added successfully" in resp.data.lower()
        assert b"E2E Investments" in resp.data

        # Use that category in a policy
        resp = client.post(
            "/add",
            data={
                "friendly_name": "E2E ISA Policy",
                "policy_number": "ISA-001",
                "insurer": "Bank Corp",
                "category": "E2E Investments",
                "start_date": "2024-01-01",
                "end_date": "2034-01-01",
                "monthly_amount": "200.00",
            },
            follow_redirects=True,
        )
        assert b"added successfully" in resp.data.lower()

        # Delete the custom category
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM categories WHERE name='E2E Investments'")
        cat_id = c.fetchone()["id"]
        conn.close()

        resp = client.get(f"/categories/delete/{cat_id}", follow_redirects=True)
        assert b"deleted successfully" in resp.data.lower()

        logout(client)


# ---------------------------------------------------------------------------
# Admin user management workflow
# ---------------------------------------------------------------------------

class TestAdminUserManagementWorkflow:

    def test_admin_adds_user_toggles_and_deletes(self, client):
        login(client)

        # Add a new user
        resp = client.post(
            "/users/add",
            data={"email": "e2euser@test.com", "password": "securepass"},
            follow_redirects=True,
        )
        assert b"added successfully" in resp.data.lower()
        assert b"e2euser@test.com" in resp.data

        # Get the new user's ID
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email='e2euser@test.com'")
        uid = c.fetchone()["id"]
        conn.close()

        # Toggle admin on
        resp = client.get(f"/users/toggle-admin/{uid}", follow_redirects=True)
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
        assert c.fetchone()["is_admin"] == 1
        conn.close()

        # Toggle admin off
        client.get(f"/users/toggle-admin/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
        assert c.fetchone()["is_admin"] == 0
        conn.close()

        # Disable the user
        client.get(f"/users/toggle/{uid}")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT enabled FROM users WHERE id=?", (uid,))
        assert c.fetchone()["enabled"] == 0
        conn.close()

        # Delete the user
        resp = client.get(f"/users/delete/{uid}", follow_redirects=True)
        assert b"deleted successfully" in resp.data.lower()

        # Confirm user is gone
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE id=?", (uid,))
        assert c.fetchone() is None
        conn.close()

        logout(client)


# ---------------------------------------------------------------------------
# Backup and restore workflow
# ---------------------------------------------------------------------------

class TestBackupAndRestoreWorkflow:

    def test_backup_download_and_restore(self, client, sample_policy):
        login(client)

        # Download JSON backup
        resp = client.get("/backup/download?type=json")
        assert resp.status_code == 200
        backup_data = json.loads(resp.data)
        # The backup exports the `name` column directly
        assert any(item["name"] == "Home Insurance" for item in backup_data["financial_items"])

        # Wipe financial items
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM financial_items")
        conn.commit()
        conn.close()

        # Confirm it's gone from the list
        resp = client.get("/policies")
        assert b"Home Insurance" not in resp.data

        # Restore from backup
        backup_bytes = json.dumps(backup_data).encode()
        resp = client.post(
            "/backup/restore",
            data={"backup_file": (io.BytesIO(backup_bytes), "backup.json")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"restored" in resp.data.lower()

        # Verify restored — name is now visible in the list
        resp = client.get("/policies")
        assert b"Home Insurance" in resp.data

        # Also verify via DB
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT name FROM financial_items WHERE name='Home Insurance'")
        assert c.fetchone() is not None
        conn.close()

        logout(client)


# ---------------------------------------------------------------------------
# Search workflow
# ---------------------------------------------------------------------------

class TestSearchWorkflow:

    def test_add_item_and_search_for_it(self, client):
        login(client)

        # Add a policy with unique searchable text
        client.post(
            "/add",
            data={
                "friendly_name": "E2E Unique SearchPolicy",
                "policy_number": "SRCH-XYZ-999",
                "insurer": "SearchCorp Ltd",
                "category": "Insurance",
                "start_date": "2024-01-01",
                "end_date": "2025-12-31",
                "monthly_amount": "25.00",
            },
        )

        # Search by name
        resp = client.get("/search?q=SearchPolicy")
        assert b"E2E Unique SearchPolicy" in resp.data

        # Search by policy number
        resp = client.get("/search?q=SRCH-XYZ-999")
        assert b"E2E Unique SearchPolicy" in resp.data

        # Search by insurer
        resp = client.get("/search?q=SearchCorp")
        assert b"E2E Unique SearchPolicy" in resp.data

        logout(client)


# ---------------------------------------------------------------------------
# Account settings workflow
# ---------------------------------------------------------------------------

class TestAccountWorkflow:

    def test_user_can_change_their_own_password(self, client):
        from werkzeug.security import generate_password_hash
        from app import get_db

        # Create a user to test with
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (email, password, is_admin, enabled) VALUES (?,?,?,?)",
            ("pwchange@test.com", generate_password_hash("oldpass"), 0, 1),
        )
        conn.commit()
        conn.close()

        # Login as that user
        login(client, "pwchange@test.com", "oldpass")

        # Change password
        resp = client.post(
            "/account",
            data={
                "email": "pwchange@test.com",
                "current_password": "oldpass",
                "new_password": "newpass456",
            },
            follow_redirects=True,
        )
        assert b"updated successfully" in resp.data.lower()

        # Logout and login with new password
        logout(client)
        resp = login(client, "pwchange@test.com", "newpass456")
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            assert "user_id" in sess

        logout(client)

    def test_wrong_current_password_rejected(self, client):
        from werkzeug.security import generate_password_hash
        from app import get_db

        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (email, password, is_admin, enabled) VALUES (?,?,?,?)",
            ("wrongpw@test.com", generate_password_hash("correct"), 0, 1),
        )
        conn.commit()
        conn.close()

        login(client, "wrongpw@test.com", "correct")

        resp = client.post(
            "/account",
            data={
                "email": "wrongpw@test.com",
                "current_password": "incorrect",
                "new_password": "newpass",
            },
            follow_redirects=True,
        )
        assert b"incorrect" in resp.data.lower()

        logout(client)


# ---------------------------------------------------------------------------
# Net worth & calendar views
# ---------------------------------------------------------------------------

class TestViewRoutes:

    def test_calendar_view_loads(self, client, sample_policy):
        login(client)
        resp = client.get("/calendar")
        assert resp.status_code == 200
        logout(client)

    def test_networth_view_loads(self, client):
        login(client)
        # Insert an item with a balance
        conn = get_db()
        c = conn.cursor()
        c.execute(
            """INSERT INTO financial_items
               (type, name, category, monthly_amount, remaining_balance,
                frequency, is_fixed_cost, is_policy, start_date, end_date,
                policy_number, insurer)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("expense", "ISA Account", "ISA", 200.0, 15000.0,
             "monthly", 1, 1, "2020-01-01", "2030-01-01", "ISA-001", "MyBank"),
        )
        conn.commit()
        conn.close()

        resp = client.get("/networth")
        assert resp.status_code == 200
        logout(client)
