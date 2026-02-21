"""
Unit tests for pure utility functions in app.py.
These tests do not touch the database or HTTP layer.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

# conftest.py already set DB_PATH and added project root to sys.path
from app import (
    calculate_days_until_expiry,
    get_valid_sort,
    get_valid_order,
    apply_expiry_filter,
    build_amount_filter_sql,
    POLICIES_SORTABLE_COLUMNS,
    EXPENSE_SORTABLE_COLUMNS,
    format_currency,
)


# ---------------------------------------------------------------------------
# calculate_days_until_expiry
# ---------------------------------------------------------------------------

class TestCalculateDaysUntilExpiry:

    def test_future_date_returns_positive(self):
        future = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        result = calculate_days_until_expiry(future)
        assert result > 0

    def test_past_date_returns_negative(self):
        past = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")
        result = calculate_days_until_expiry(past)
        assert result < 0

    def test_today_returns_zero(self):
        today = datetime.now().strftime("%Y-%m-%d")
        result = calculate_days_until_expiry(today)
        assert result == 0

    def test_exact_30_days_future(self):
        future = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        result = calculate_days_until_expiry(future)
        assert result == 30

    def test_invalid_date_returns_zero(self):
        result = calculate_days_until_expiry("not-a-date")
        assert result == 0

    def test_none_returns_zero(self):
        result = calculate_days_until_expiry(None)
        assert result == 0

    def test_empty_string_returns_zero(self):
        result = calculate_days_until_expiry("")
        assert result == 0

    def test_wrong_format_returns_zero(self):
        result = calculate_days_until_expiry("31/12/2025")
        assert result == 0


# ---------------------------------------------------------------------------
# get_valid_sort
# ---------------------------------------------------------------------------

class TestGetValidSort:

    def test_valid_policy_column_returns_sql_column(self):
        result = get_valid_sort("name", POLICIES_SORTABLE_COLUMNS)
        assert result == "name"

    def test_valid_column_maps_to_correct_sql(self):
        result = get_valid_sort("provider", POLICIES_SORTABLE_COLUMNS)
        assert result == "insurer"

    def test_invalid_column_returns_default(self):
        result = get_valid_sort("nonexistent", POLICIES_SORTABLE_COLUMNS, default="end_date")
        assert result == POLICIES_SORTABLE_COLUMNS["end_date"]

    def test_none_column_returns_default(self):
        result = get_valid_sort(None, POLICIES_SORTABLE_COLUMNS, default="name")
        assert result == "name"

    def test_empty_column_returns_default(self):
        result = get_valid_sort("", POLICIES_SORTABLE_COLUMNS, default="name")
        assert result == "name"

    def test_sql_injection_attempt_returns_default(self):
        result = get_valid_sort("name; DROP TABLE policies--", POLICIES_SORTABLE_COLUMNS, default="name")
        assert result == "name"

    def test_expense_sort_amount_maps_to_monthly_amount(self):
        result = get_valid_sort("amount", EXPENSE_SORTABLE_COLUMNS, default="name")
        assert result == "monthly_amount"

    def test_all_policy_columns_valid(self):
        for key, expected in POLICIES_SORTABLE_COLUMNS.items():
            assert get_valid_sort(key, POLICIES_SORTABLE_COLUMNS) == expected


# ---------------------------------------------------------------------------
# get_valid_order
# ---------------------------------------------------------------------------

class TestGetValidOrder:

    def test_asc_returns_asc(self):
        from app import get_valid_order
        assert get_valid_order("asc") == "asc"

    def test_desc_returns_desc(self):
        from app import get_valid_order
        assert get_valid_order("desc") == "desc"

    def test_uppercase_asc_is_accepted(self):
        from app import get_valid_order
        assert get_valid_order("ASC") == "asc"

    def test_uppercase_desc_is_accepted(self):
        from app import get_valid_order
        assert get_valid_order("DESC") == "desc"

    def test_invalid_order_returns_default(self):
        from app import get_valid_order
        assert get_valid_order("INVALID") == "asc"

    def test_none_returns_default(self):
        from app import get_valid_order
        assert get_valid_order(None) == "asc"

    def test_custom_default(self):
        from app import get_valid_order
        assert get_valid_order(None, default="desc") == "desc"

    def test_sql_injection_returns_default(self):
        from app import get_valid_order
        assert get_valid_order("asc; DROP TABLE--") == "asc"


# ---------------------------------------------------------------------------
# apply_expiry_filter
# ---------------------------------------------------------------------------

class TestApplyExpiryFilter:

    def _make_policy(self, days):
        return {"days_until_expiry": days, "name": f"Policy {days}d"}

    def test_no_filters_returns_all(self):
        policies = [self._make_policy(d) for d in [-5, 10, 60]]
        result = apply_expiry_filter(policies, [])
        assert len(result) == 3

    def test_expired_filter(self):
        policies = [self._make_policy(d) for d in [-5, 10, 60]]
        result = apply_expiry_filter(policies, ["expired"])
        assert len(result) == 1
        assert result[0]["days_until_expiry"] < 0

    def test_soon_filter_includes_0_to_29(self):
        policies = [self._make_policy(d) for d in [-1, 0, 15, 29, 30]]
        result = apply_expiry_filter(policies, ["soon"])
        days = [p["days_until_expiry"] for p in result]
        assert 0 in days
        assert 15 in days
        assert 29 in days
        assert -1 not in days
        assert 30 not in days

    def test_active_filter_includes_30_plus(self):
        policies = [self._make_policy(d) for d in [29, 30, 365]]
        result = apply_expiry_filter(policies, ["active"])
        days = [p["days_until_expiry"] for p in result]
        assert 30 in days
        assert 365 in days
        assert 29 not in days

    def test_combined_filters(self):
        policies = [self._make_policy(d) for d in [-5, 10, 60]]
        result = apply_expiry_filter(policies, ["expired", "soon"])
        days = {p["days_until_expiry"] for p in result}
        assert -5 in days
        assert 10 in days
        assert 60 not in days

    def test_all_filters_returns_all(self):
        policies = [self._make_policy(d) for d in [-5, 10, 60]]
        result = apply_expiry_filter(policies, ["expired", "soon", "active"])
        assert len(result) == 3

    def test_empty_list_returns_empty(self):
        result = apply_expiry_filter([], ["expired"])
        assert result == []


# ---------------------------------------------------------------------------
# build_amount_filter_sql
# ---------------------------------------------------------------------------

class TestBuildAmountFilterSql:

    def test_under100(self):
        sql = build_amount_filter_sql("under100")
        assert "< 100" in sql

    def test_100_to_500(self):
        sql = build_amount_filter_sql("100-500")
        assert "BETWEEN 100 AND 500" in sql

    def test_500_to_1000(self):
        sql = build_amount_filter_sql("500-1000")
        assert "BETWEEN 500 AND 1000" in sql

    def test_over1000(self):
        sql = build_amount_filter_sql("over1000")
        assert "> 1000" in sql

    def test_none_returns_none(self):
        assert build_amount_filter_sql(None) is None

    def test_empty_string_returns_none(self):
        assert build_amount_filter_sql("") is None

    def test_invalid_value_returns_none(self):
        assert build_amount_filter_sql("invalid_range") is None

    def test_all_results_contain_monthly_amount(self):
        ranges = ["under100", "100-500", "500-1000", "over1000"]
        for r in ranges:
            result = build_amount_filter_sql(r)
            assert "monthly_amount" in result


# ---------------------------------------------------------------------------
# format_currency template filter
# ---------------------------------------------------------------------------

class TestFormatCurrency:

    def test_none_returns_dash(self, auth_client):
        # Uses Flask's app context because the filter reads a setting from DB
        from app import app
        with app.app_context():
            result = format_currency(None)
        assert result == "-"

    def test_positive_value(self, auth_client):
        from app import app
        with app.app_context():
            result = format_currency(1234.5)
        assert "1,234.50" in result

    def test_zero_value(self, auth_client):
        from app import app
        with app.app_context():
            result = format_currency(0)
        assert "0.00" in result

    def test_negative_value(self, auth_client):
        from app import app
        with app.app_context():
            result = format_currency(-99.99)
        assert "99.99" in result
