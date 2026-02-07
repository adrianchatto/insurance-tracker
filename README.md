# Policy Tracker

A comprehensive Flask-based application for tracking insurance policies, mortgages, utilities, subscriptions, warranties, and any recurring contracts with integrated budget management and net worth tracking.

## Features

### Budget & Financial Management
- **Budget Tracker**: Track income sources and expenses with comprehensive financial overview
- **Policy Integration**: Toggle any expense to flag as a policy for unified tracking
- **Financial Summaries**: Real-time totals for income, expenses, fixed costs, and discretionary spending
- **Interactive Charts**: Visual breakdown of expenses by category and type
- **Pagination**: Customizable items per page (10, 25, 50, 100)

### Policy Management
- **Multi-Category Support**: Track any type of recurring policy or contract
- **Friendly Names**: Human-readable labels for easy identification
- **Financial Tracking**: Automatic monthly/annual amount calculations
- **Expiry Tracking**: Visual indicators for expired and expiring policies
- **Balance Tracking**: Track balances for all account types (ISAs, Pensions, Mortgages, etc.)

### Net Worth Tracking (New in v2.1.0)
- **Asset Management**: Track ISAs, Pensions, and other investment accounts
- **Liability Management**: Monitor mortgage debt and loans
- **Net Worth Calculator**: Automatic calculation of total assets minus liabilities
- **Separate Views**: Clear separation of assets and liabilities with color-coded tables
- **Summary Dashboard**: Quick overview cards showing total assets, liabilities, and net worth
- **Flexible Date Fields**: Optional start/end dates for accounts (auto-populated if left blank)

### Advanced Organization
- **Table Sorting**: Sort by any column (name, amount, date, provider, category, frequency)
- **Comprehensive Filtering**:
  - **Policies**: Filter by category, expiry status, provider, and amount range
  - **Budget**: Filter by type (fixed/discretionary), frequency, and amount range
- **Multi-Select Filters**: Combine multiple filter criteria with active filter badges
- **Global Search**: Quick search across all policies and budget items
- **Calendar View**: Visual timeline showing policy coverage periods

### System Features
- **Category Management**: Create custom categories with color coding
- **User Management**: Multi-user support with admin roles
- **Email Notifications**: Get alerts for expiring policies
- **Backup & Restore**: Full data backup and restore capabilities (DB and JSON formats)
- **Account Settings**: Email and password management
- **Responsive Design**: Clean, modern interface with Tailwind CSS

## User Interface

- **Budget** (Default Landing Page): Comprehensive financial overview with charts and summaries
- **Policies**: Dedicated policy management with filtering and sorting
- **Net Worth**: Track assets (ISAs, Pensions) and liabilities (Mortgages) with automatic net worth calculation
- **Calendar**: Visual timeline view of policy coverage periods
- **Categories**: Manage and color-code your categories
- **Admin Panel**: User management, settings, and backup tools

## Default Login

- Email: `admin@policytracker.local`
- Password: `admin`

**Important:** Change the default password immediately after first login!

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python app.py`

## Environment Variables

- `SECRET_KEY`: Flask secret key (change in production)
- `DB_PATH`: Database file path (default: `/data/policies.db`)

## Docker Deployment

See deployment instructions for Docker setup.
