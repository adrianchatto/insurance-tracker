# Policy Tracker

A comprehensive Flask-based application for tracking insurance policies, mortgages, utilities, subscriptions, warranties, and any recurring contracts.

## Features

- **Multi-Category Support**: Track any type of recurring policy or contract
- **Friendly Names**: Human-readable labels for easy identification
- **Financial Tracking**: Automatic monthly/annual amount calculations
- **Category Management**: Create custom categories and filter by them
- **User Management**: Multi-user support with admin roles
- **Email Notifications**: Get alerts for expiring policies
- **Backup & Restore**: Full data backup and restore capabilities
- **Account Settings**: Simple email and password management

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
