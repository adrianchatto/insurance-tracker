from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
from datetime import datetime, timedelta
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Database configuration
DB_PATH = os.environ.get('DB_PATH', '/data/policies.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Check if old tables exist (for migration)
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='policies'")
    old_policies_exists = c.fetchone() is not None
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='budget_items'")
    old_budget_items_exists = c.fetchone() is not None

    # Create unified financial_items table
    c.execute('''CREATE TABLE IF NOT EXISTS financial_items
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
                  name TEXT NOT NULL,
                  category TEXT,
                  notes TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  monthly_amount REAL,
                  annual_amount REAL,
                  frequency TEXT DEFAULT 'monthly' CHECK(frequency IN ('monthly', 'annual', 'one-time')),
                  is_fixed_cost INTEGER DEFAULT 0,
                  is_policy INTEGER DEFAULT 0,
                  policy_number TEXT,
                  insurer TEXT,
                  start_date TEXT,
                  end_date TEXT,
                  remaining_balance REAL,
                  account_source TEXT,
                  insurer_website TEXT)''')

    # Migrate data from old tables if they exist
    if old_policies_exists and old_budget_items_exists:
        # Check if financial_items is empty (migration not done yet)
        c.execute("SELECT COUNT(*) FROM financial_items")
        if c.fetchone()[0] == 0:
            print("Migrating data from old schema to unified financial_items table...")

            # Migrate policies
            c.execute('''INSERT INTO financial_items
                        (type, name, category, notes, created_at,
                         monthly_amount, annual_amount, frequency, is_fixed_cost,
                         is_policy, policy_number, insurer, start_date, end_date,
                         remaining_balance, account_source, insurer_website)
                        SELECT 'expense', friendly_name, category, notes, created_at,
                               monthly_amount, annual_amount, 'monthly', 1,
                               1, policy_number, insurer, start_date, end_date,
                               remaining_balance, account_source, insurer_website
                        FROM policies''')

            # Migrate budget_items (excluding duplicates linked from policies)
            c.execute('''INSERT INTO financial_items
                        (type, name, category, notes, created_at,
                         monthly_amount, frequency, is_fixed_cost, is_policy)
                        SELECT type, name, category, notes, created_at,
                               amount, frequency, is_fixed_cost, 0
                        FROM budget_items
                        WHERE NOT EXISTS (
                            SELECT 1 FROM policies
                            WHERE policies.friendly_name = budget_items.name
                            AND budget_items.notes LIKE 'Linked from policy:%'
                        )''')

            conn.commit()
            print(f"Migration complete. Migrated data to financial_items table.")

            # Drop old tables
            c.execute("DROP TABLE IF EXISTS policies")
            c.execute("DROP TABLE IF EXISTS budget_items")
            print("Dropped old tables: policies and budget_items")

    # Create indexes for performance
    c.execute("CREATE INDEX IF NOT EXISTS idx_is_policy ON financial_items(is_policy)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_type_is_policy ON financial_items(type, is_policy)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_is_policy_end_date ON financial_items(is_policy, end_date)")

    # Create compatibility views for rollback safety
    c.execute('''CREATE VIEW IF NOT EXISTS policies AS
                 SELECT id, name as friendly_name, policy_number, insurer, category,
                        start_date, end_date, monthly_amount, annual_amount,
                        remaining_balance, account_source, insurer_website, notes, created_at
                 FROM financial_items
                 WHERE is_policy = 1''')

    c.execute('''CREATE VIEW IF NOT EXISTS budget_items AS
                 SELECT id, type, name, monthly_amount as amount, category,
                        frequency, is_fixed_cost, notes, created_at
                 FROM financial_items
                 WHERE is_policy = 0''')

    # Create categories table
    c.execute('''CREATE TABLE IF NOT EXISTS categories
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  color TEXT DEFAULT '#3B82F6',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Create users table (email as username)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0,
                  enabled INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Create settings table
    c.execute('''CREATE TABLE IF NOT EXISTS settings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  key TEXT UNIQUE NOT NULL,
                  value TEXT NOT NULL)''')

    # Check if admin user exists
    c.execute("SELECT * FROM users WHERE email = 'admin@policytracker.local'")
    if not c.fetchone():
        hashed_password = generate_password_hash('admin')
        c.execute("INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)",
                 ('admin@policytracker.local', hashed_password, 1))
    
    # Initialize default categories with colors
    default_categories = [
        ('Mortgage', '#10B981'),      # Green
        ('Insurance', '#3B82F6'),     # Blue
        ('Utilities', '#F59E0B'),     # Orange
        ('Subscriptions', '#8B5CF6'), # Purple
        ('Warranties', '#EC4899'),    # Pink
        ('Other', '#6B7280')          # Gray
    ]
    for category, color in default_categories:
        c.execute("INSERT OR IGNORE INTO categories (name, color) VALUES (?, ?)", (category, color))

    # Update existing categories with default color if they don't have one
    c.execute("UPDATE categories SET color = '#3B82F6' WHERE color IS NULL OR color = ''")
    
    # Initialize default settings
    default_settings = {
        'notification_days': '30',
        'notification_enabled': 'true',
        'smtp_server': '',
        'smtp_port': '587',
        'smtp_username': '',
        'smtp_password': '',
        'smtp_from_email': '',
        'smtp_use_tls': 'true',
        'currency_symbol': '$',
        'currency_code': 'USD'
    }
    
    for key, value in default_settings.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
    
    conn.commit()
    conn.close()

init_db()

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.template_filter('format_currency')
def format_currency(value):
    if value is None:
        return '-'
    currency_symbol = get_setting('currency_symbol', '$')
    return f"{currency_symbol}{value:,.2f}"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT enabled FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or not user['enabled']:
            session.clear()
            flash('Your account has been disabled.', 'error')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT is_admin, enabled FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        
        if not user or not user['enabled']:
            session.clear()
            flash('Your account has been disabled.', 'error')
            return redirect(url_for('login'))
        
        if not user['is_admin']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_setting(key, default=''):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    result = c.fetchone()
    conn.close()
    return result['value'] if result else default

def set_setting(key, value):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

def calculate_days_until_expiry(end_date_str):
    try:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        today = datetime.now().date()
        return (end_date - today).days
    except:
        return 0

@app.route('/')
@login_required
def index():
    category_filter = request.args.get('category', '')
    
    conn = get_db()
    c = conn.cursor()
    
    if category_filter:
        c.execute("SELECT * FROM financial_items WHERE is_policy = 1 AND category = ? ORDER BY end_date", (category_filter,))
    else:
        c.execute("SELECT * FROM financial_items WHERE is_policy = 1 ORDER BY end_date")
    
    policies = c.fetchall()

    c.execute("SELECT name, color FROM categories ORDER BY name")
    categories = c.fetchall()

    conn.close()

    # Add days until expiry and category color to each policy
    policies_with_days = []
    categories_dict = {cat['name']: cat['color'] for cat in categories}
    for policy in policies:
        policy_dict = dict(policy)
        policy_dict['days_until_expiry'] = calculate_days_until_expiry(policy['end_date'])
        policy_dict['category_color'] = categories_dict.get(policy['category'], '#3B82F6')
        policies_with_days.append(policy_dict)
    
    return render_template('index.html', policies=policies_with_days, categories=categories, selected_category=category_filter)

@app.route('/calendar')
@login_required
def calendar():
    conn = get_db()
    c = conn.cursor()

    # Get all policies ordered by category and start date
    c.execute("SELECT * FROM financial_items WHERE is_policy = 1 ORDER BY category, start_date")
    policies = c.fetchall()

    # Get categories for grouping and colors
    c.execute("SELECT name, color FROM categories ORDER BY name")
    categories = c.fetchall()

    conn.close()

    # Enrich policies with category colors and days until expiry
    categories_dict = {cat['name']: cat['color'] for cat in categories}
    policies_enhanced = []
    for policy in policies:
        policy_dict = dict(policy)
        policy_dict['days_until_expiry'] = calculate_days_until_expiry(policy['end_date'])
        policy_dict['category_color'] = categories_dict.get(policy['category'], '#3B82F6')
        policies_enhanced.append(policy_dict)

    # Group policies by category for timeline rendering
    policies_by_category = {}
    for category in categories:
        policies_by_category[category['name']] = []

    for policy in policies_enhanced:
        cat = policy['category']
        if cat in policies_by_category:
            policies_by_category[cat].append(policy)

    return render_template('calendar.html',
                          policies_by_category=policies_by_category,
                          categories=categories,
                          all_policies=policies_enhanced)

@app.route('/budget')
@login_required
def budget():
    conn = get_db()
    c = conn.cursor()

    # Get pagination parameters
    expenses_page = request.args.get('expenses_page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # Validate per_page values
    if per_page not in [10, 25, 50, 100]:
        per_page = 10

    # Get all financial items (includes policies, expenses, and income)
    c.execute("SELECT *, name as friendly_name, monthly_amount as amount FROM financial_items ORDER BY type, category, name")
    items = c.fetchall()

    # Get categories for dropdown
    c.execute("SELECT name, color FROM categories ORDER BY name")
    categories = c.fetchall()

    conn.close()

    # Separate income and expenses (expenses include policies)
    income_items = [dict(item) for item in items if item['type'] == 'income']
    all_expense_items = [dict(item) for item in items if item['type'] == 'expense']

    # Calculate totals (use all items, not paginated)
    total_income = sum(item['amount'] or 0 for item in income_items)
    total_expenses = sum(item['amount'] or 0 for item in all_expense_items)
    fixed_costs = sum(item['amount'] or 0 for item in all_expense_items if item['is_fixed_cost'])
    discretionary = sum(item['amount'] or 0 for item in all_expense_items if not item['is_fixed_cost'])

    # Group expenses by category for pie chart
    expenses_by_category = {}
    for item in all_expense_items:
        cat = item['category'] or 'Other'
        if cat not in expenses_by_category:
            expenses_by_category[cat] = 0
        expenses_by_category[cat] += (item['amount'] or 0)

    # Paginate expenses
    expenses_total = len(all_expense_items)
    expenses_total_pages = (expenses_total + per_page - 1) // per_page
    expenses_start = (expenses_page - 1) * per_page
    expenses_end = expenses_start + per_page
    expense_items = all_expense_items[expenses_start:expenses_end]

    return render_template('budget.html',
                          income_items=income_items,
                          expense_items=expense_items,
                          categories=categories,
                          total_income=total_income,
                          total_expenses=total_expenses,
                          fixed_costs=fixed_costs,
                          discretionary=discretionary,
                          expenses_by_category=expenses_by_category,
                          net_income=total_income - total_expenses,
                          expenses_page=expenses_page,
                          per_page=per_page,
                          expenses_total=expenses_total,
                          expenses_total_pages=expenses_total_pages)

@app.route('/budget/add', methods=['POST'])
@login_required
def add_budget_item():
    item_type = request.form.get('type')
    name = request.form.get('name')
    amount = request.form.get('amount')
    category = request.form.get('category')
    frequency = request.form.get('frequency', 'monthly')
    is_fixed_cost = 1 if 'is_fixed_cost' in request.form else 0
    notes = request.form.get('notes')

    if not all([item_type, name, amount]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('budget'))

    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT INTO financial_items (type, name, monthly_amount, category, frequency, is_fixed_cost, notes, is_policy)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
             (item_type, name, float(amount), category, frequency, is_fixed_cost, notes, 0))
    conn.commit()
    conn.close()

    flash(f'{"Income" if item_type == "income" else "Expense"} added successfully!', 'success')
    return redirect(url_for('budget'))

@app.route('/budget/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_budget_item(id):
    conn = get_db()
    c = conn.cursor()

    if request.method == 'POST':
        item_type = request.form.get('type')
        name = request.form.get('name')
        amount = request.form.get('amount')
        category = request.form.get('category')
        frequency = request.form.get('frequency', 'monthly')
        is_fixed_cost = 1 if 'is_fixed_cost' in request.form else 0
        notes = request.form.get('notes')

        if not all([item_type, name, amount]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('budget'))

        c.execute("""UPDATE financial_items
                     SET type=?, name=?, monthly_amount=?, category=?, frequency=?, is_fixed_cost=?, notes=?
                     WHERE id=? AND is_policy=0""",
                 (item_type, name, float(amount), category, frequency, is_fixed_cost, notes, id))
        conn.commit()
        conn.close()

        flash(f'{"Income" if item_type == "income" else "Expense"} updated successfully!', 'success')
        return redirect(url_for('budget'))

    # GET request - fetch item data
    c.execute("SELECT *, monthly_amount as amount FROM financial_items WHERE id=? AND is_policy=0", (id,))
    item = c.fetchone()
    conn.close()

    if not item:
        flash('Item not found.', 'error')
        return redirect(url_for('budget'))

    # Return JSON for AJAX request
    return {
        'id': item['id'],
        'type': item['type'],
        'name': item['name'],
        'amount': item['amount'],
        'category': item['category'],
        'frequency': item['frequency'],
        'is_fixed_cost': item['is_fixed_cost'],
        'notes': item['notes']
    }

@app.route('/budget/delete/<int:id>')
@login_required
def delete_budget_item(id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM financial_items WHERE id=?", (id,))
    conn.commit()
    conn.close()

    flash('Item deleted successfully!', 'success')
    return redirect(url_for('budget'))

@app.route('/add', methods=['POST'])
@login_required
def add_policy():
    friendly_name = request.form.get('friendly_name')
    policy_number = request.form.get('policy_number')
    insurer = request.form.get('insurer')
    category = request.form.get('category')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    monthly_amount = request.form.get('monthly_amount') or None
    annual_amount = request.form.get('annual_amount') or None
    remaining_balance = request.form.get('remaining_balance') or None
    account_source = request.form.get('account_source')
    insurer_website = request.form.get('insurer_website')
    notes = request.form.get('notes')

    # Calculate the other amount if one is provided
    if monthly_amount and not annual_amount:
        annual_amount = float(monthly_amount) * 12
    elif annual_amount and not monthly_amount:
        monthly_amount = float(annual_amount) / 12

    if not all([friendly_name, policy_number, insurer, category, start_date, end_date]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT INTO financial_items (type, name, policy_number, insurer, category, start_date, end_date,
                 monthly_amount, annual_amount, remaining_balance, account_source, insurer_website, notes,
                 frequency, is_fixed_cost, is_policy)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
             ('expense', friendly_name, policy_number, insurer, category, start_date, end_date,
              monthly_amount, annual_amount, remaining_balance, account_source, insurer_website, notes,
              'monthly', 1, 1))
    conn.commit()
    conn.close()
    
    flash('Policy added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_policy(id):
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        friendly_name = request.form.get('friendly_name')
        policy_number = request.form.get('policy_number')
        insurer = request.form.get('insurer')
        category = request.form.get('category')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        monthly_amount = request.form.get('monthly_amount') or None
        annual_amount = request.form.get('annual_amount') or None
        remaining_balance = request.form.get('remaining_balance') or None
        account_source = request.form.get('account_source')
        insurer_website = request.form.get('insurer_website')
        notes = request.form.get('notes')

        # Calculate the other amount if one is provided
        if monthly_amount and not annual_amount:
            annual_amount = float(monthly_amount) * 12
        elif annual_amount and not monthly_amount:
            monthly_amount = float(annual_amount) / 12

        if not all([friendly_name, policy_number, insurer, category, start_date, end_date]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('edit_policy', id=id))

        c.execute("""UPDATE financial_items
                     SET name=?, policy_number=?, insurer=?, category=?, start_date=?, end_date=?,
                         monthly_amount=?, annual_amount=?, remaining_balance=?, account_source=?, insurer_website=?, notes=?
                     WHERE id=? AND is_policy=1""",
                 (friendly_name, policy_number, insurer, category, start_date, end_date,
                  monthly_amount, annual_amount, remaining_balance, account_source, insurer_website, notes, id))
        conn.commit()
        conn.close()
        
        flash('Policy updated successfully!', 'success')
        return redirect(url_for('index'))
    
    c.execute("SELECT * FROM financial_items WHERE id=? AND is_policy=1", (id,))
    policy = c.fetchone()

    c.execute("SELECT name, color FROM categories ORDER BY name")
    categories = c.fetchall()

    conn.close()

    if not policy:
        flash('Policy not found.', 'error')
        return redirect(url_for('index'))

    return render_template('edit.html', policy=policy, categories=categories)

@app.route('/delete/<int:id>')
@login_required
def delete_policy(id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM financial_items WHERE id=? AND is_policy=1", (id,))
    conn.commit()
    conn.close()
    
    flash('Policy deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if request.method == 'POST':
        category_name = request.form.get('category_name')
        if category_name:
            conn = get_db()
            c = conn.cursor()
            try:
                c.execute("INSERT INTO categories (name) VALUES (?)", (category_name,))
                conn.commit()
                flash('Category added successfully!', 'success')
            except sqlite3.IntegrityError:
                flash('Category already exists.', 'error')
            conn.close()
        return redirect(url_for('manage_categories'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM categories ORDER BY name")
    categories = c.fetchall()
    conn.close()
    
    return render_template('categories.html', categories=categories)

@app.route('/categories/delete/<int:id>')
@login_required
def delete_category(id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM categories WHERE id=?", (id,))
    conn.commit()
    conn.close()
    
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('manage_categories'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            if not user['enabled']:
                flash('Your account has been disabled.', 'error')
                return redirect(url_for('login'))
            
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['is_admin'] = user['is_admin']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        new_email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect.', 'error')
            conn.close()
            return redirect(url_for('account'))
        
        # Update email if changed
        if new_email and new_email != user['email']:
            try:
                c.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, session['user_id']))
                session['email'] = new_email
                flash('Email updated successfully!', 'success')
            except sqlite3.IntegrityError:
                flash('Email already in use.', 'error')
                conn.close()
                return redirect(url_for('account'))
        
        # Update password if provided
        if new_password:
            hashed_password = generate_password_hash(new_password)
            c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, session['user_id']))
            flash('Password updated successfully!', 'success')
        
        conn.commit()
        conn.close()
        return redirect(url_for('account'))
    
    return render_template('account.html')

@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    if request.method == 'POST':
        notification_days = request.form.get('notification_days', '30')
        notification_enabled = 'notification_enabled' in request.form
        smtp_server = request.form.get('smtp_server', '')
        smtp_port = request.form.get('smtp_port', '587')
        smtp_username = request.form.get('smtp_username', '')
        smtp_password = request.form.get('smtp_password', '')
        smtp_from_email = request.form.get('smtp_from_email', '')
        smtp_use_tls = 'smtp_use_tls' in request.form
        currency_symbol = request.form.get('currency_symbol', '$')
        currency_code = request.form.get('currency_code', 'USD')
        
        set_setting('notification_days', notification_days)
        set_setting('notification_enabled', 'true' if notification_enabled else 'false')
        set_setting('smtp_server', smtp_server)
        set_setting('smtp_port', smtp_port)
        set_setting('smtp_username', smtp_username)
        if smtp_password:
            set_setting('smtp_password', smtp_password)
        set_setting('smtp_from_email', smtp_from_email)
        set_setting('smtp_use_tls', 'true' if smtp_use_tls else 'false')
        set_setting('currency_symbol', currency_symbol)
        set_setting('currency_code', currency_code)
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    
    current_settings = {
        'notification_days': get_setting('notification_days', '30'),
        'notification_enabled': get_setting('notification_enabled', 'true') == 'true',
        'smtp_server': get_setting('smtp_server', ''),
        'smtp_port': get_setting('smtp_port', '587'),
        'smtp_username': get_setting('smtp_username', ''),
        'smtp_from_email': get_setting('smtp_from_email', ''),
        'smtp_use_tls': get_setting('smtp_use_tls', 'true') == 'true',
        'currency_symbol': get_setting('currency_symbol', '$'),
        'currency_code': get_setting('currency_code', 'USD')
    }
    
    return render_template('settings.html', settings=current_settings)

@app.route('/users')
@admin_required
def users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, is_admin, enabled, created_at FROM users ORDER BY created_at DESC")
    users_list = c.fetchall()
    conn.close()
    
    return render_template('users.html', users=users_list)

@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = 'is_admin' in request.form
    
    if not email or not password:
        flash('Email and password are required.', 'error')
        return redirect(url_for('users'))
    
    hashed_password = generate_password_hash(password)
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)",
                 (email, hashed_password, 1 if is_admin else 0))
        conn.commit()
        conn.close()
        flash('User added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists.', 'error')
    
    return redirect(url_for('users'))

@app.route('/users/toggle-admin/<int:id>')
@admin_required
def toggle_admin(id):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin = NOT is_admin WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    
    flash('User admin status updated successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/users/toggle/<int:id>')
@admin_required
def toggle_user(id):
    if id == session['user_id']:
        flash('You cannot disable your own account.', 'error')
        return redirect(url_for('users'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET enabled = NOT enabled WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    
    flash('User status updated successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:id>')
@admin_required
def delete_user(id):
    if id == session['user_id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as count FROM users WHERE is_admin = 1 AND enabled = 1")
    admin_count = c.fetchone()['count']
    
    c.execute("SELECT is_admin FROM users WHERE id = ?", (id,))
    user = c.fetchone()
    
    if user and user['is_admin'] and admin_count <= 1:
        conn.close()
        flash('Cannot delete the last admin user.', 'error')
        return redirect(url_for('users'))
    
    c.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/backup')
@admin_required
def backup():
    return render_template('backup.html')

@app.route('/backup/download')
@admin_required
def download_backup():
    backup_type = request.args.get('type', 'db')
    
    if backup_type == 'db':
        return send_file(DB_PATH, as_attachment=True, download_name='policy_tracker_backup.db')
    else:
        conn = get_db()
        c = conn.cursor()
        
        # Backup financial_items (unified table)
        c.execute("SELECT * FROM financial_items")
        financial_items = [dict(row) for row in c.fetchall()]

        c.execute("SELECT id, email, is_admin, enabled, created_at FROM users")
        users = [dict(row) for row in c.fetchall()]

        c.execute("SELECT * FROM categories")
        categories = [dict(row) for row in c.fetchall()]

        c.execute("SELECT * FROM settings")
        settings = [dict(row) for row in c.fetchall()]

        conn.close()

        backup_data = {
            'backup_date': datetime.now().isoformat(),
            'version': '2.0',  # Mark as new format
            'financial_items': financial_items,
            'users': users,
            'categories': categories,
            'settings': settings
        }
        
        json_path = '/tmp/policy_tracker_backup.json'
        with open(json_path, 'w') as f:
            json.dump(backup_data, f, indent=2)
        
        return send_file(json_path, as_attachment=True, download_name='policy_tracker_backup.json')

@app.route('/backup/restore', methods=['POST'])
@admin_required
def restore_backup():
    if 'backup_file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('backup'))
    
    file = request.files['backup_file']
    
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('backup'))
    
    try:
        if file.filename.endswith('.db'):
            # Save to temporary location first
            import tempfile
            import shutil
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            file.save(temp_db.name)
            temp_db.close()

            # Replace database file
            shutil.move(temp_db.name, DB_PATH)

            # Trigger migration by running init_db
            init_db()

            flash('Database restored successfully!', 'success')
        elif file.filename.endswith('.json'):
            backup_data = json.load(file)
            
            conn = get_db()
            c = conn.cursor()

            # Clear existing data
            c.execute("DELETE FROM financial_items")
            c.execute("DELETE FROM categories")
            c.execute("DELETE FROM settings")

            # Check if this is a new format backup (v2.0) or old format
            if 'financial_items' in backup_data:
                # New format - restore financial_items directly
                for item in backup_data.get('financial_items', []):
                    c.execute("""INSERT INTO financial_items
                               (id, type, name, category, notes, created_at,
                                monthly_amount, annual_amount, frequency, is_fixed_cost, is_policy,
                                policy_number, insurer, start_date, end_date,
                                remaining_balance, account_source, insurer_website)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                             (item.get('id'), item.get('type'), item.get('name'), item.get('category'),
                              item.get('notes'), item.get('created_at'), item.get('monthly_amount'),
                              item.get('annual_amount'), item.get('frequency'), item.get('is_fixed_cost'),
                              item.get('is_policy'), item.get('policy_number'), item.get('insurer'),
                              item.get('start_date'), item.get('end_date'), item.get('remaining_balance'),
                              item.get('account_source'), item.get('insurer_website')))
            else:
                # Old format - migrate policies and budget_items to financial_items
                for policy in backup_data.get('policies', []):
                    c.execute("""INSERT INTO financial_items
                               (id, type, name, category, notes, created_at,
                                monthly_amount, annual_amount, frequency, is_fixed_cost, is_policy,
                                policy_number, insurer, start_date, end_date,
                                remaining_balance, account_source, insurer_website)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                             (policy.get('id'), 'expense', policy.get('friendly_name'), policy.get('category'),
                              policy.get('notes'), policy.get('created_at'), policy.get('monthly_amount'),
                              policy.get('annual_amount'), 'monthly', 1, 1,
                              policy.get('policy_number'), policy.get('insurer'), policy.get('start_date'),
                              policy.get('end_date'), policy.get('remaining_balance'),
                              policy.get('account_source'), policy.get('insurer_website')))

                # Migrate budget_items if they exist in backup
                for item in backup_data.get('budget_items', []):
                    c.execute("""INSERT INTO financial_items
                               (id, type, name, category, notes, created_at,
                                monthly_amount, frequency, is_fixed_cost, is_policy)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                             (item.get('id'), item.get('type'), item.get('name'),
                              item.get('category'), item.get('notes'), item.get('created_at'),
                              item.get('amount'), item.get('frequency'), item.get('is_fixed_cost'), 0))

            # Restore categories
            for category in backup_data.get('categories', []):
                c.execute("INSERT INTO categories (id, name, created_at) VALUES (?, ?, ?)",
                         (category.get('id'), category.get('name'), category.get('created_at')))

            # Restore settings
            for setting in backup_data.get('settings', []):
                c.execute("INSERT INTO settings (key, value) VALUES (?, ?)",
                         (setting.get('key'), setting.get('value')))

            conn.commit()
            conn.close()
            
            flash('Backup restored successfully!', 'success')
        else:
            flash('Invalid file format. Please upload a .db or .json file.', 'error')
    except Exception as e:
        flash(f'Error restoring backup: {str(e)}', 'error')
    
    return redirect(url_for('backup'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
