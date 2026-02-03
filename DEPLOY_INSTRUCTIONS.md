# Complete Deployment Instructions for Policy Tracker

## Features Included

✅ Renamed to "Policy Tracker" (not just insurance)
✅ Support for any recurring policy/contract (mortgage, utilities, subscriptions, warranties)
✅ Friendly names for policies
✅ Notes field per policy
✅ Monthly/Annual amount auto-calculation
✅ Category dropdown with ability to add custom categories
✅ Filter policies by category
✅ Email-based authentication
✅ Simple account settings (update email/password)
✅ Admin can make other users admin
✅ Admin can disable any account (except their own)
✅ Admin can change any user's admin status
✅ Currency support (10+ currencies with custom symbols)
✅ Modern logo integrated throughout
✅ Clean, professional UI
✅ docker-compose.yml INCLUDED in package

## Deployment Steps

### 1. On Your Mac - Push to GitHub

```bash
cd ~/Downloads
tar -xzf policy-tracker-full-with-currency.tar.gz
cd policy-tracker-full

# Initialize git and push
git init
git add .
git commit -m "Complete Policy Tracker with all features"
git remote add origin https://github.com/adrianchatto/insurance-tracker.git
git branch -m master main
git push -u origin main --force
```

### 2. On Your Server - Deploy with Docker

**Option A: Using the included docker-compose.yml**

SSH to your server and copy the docker-compose.yml:
```bash
ssh adrianchatto@172.22.30.10

# Create directory
sudo mkdir -p /data/compose/7

# Copy docker-compose.yml from your local machine
# (SCP it or copy/paste content)
```

From your Mac, SCP the file:
```bash
scp ~/Downloads/policy-tracker-full/docker-compose.yml adrianchatto@172.22.30.10:/tmp/
ssh adrianchatto@172.22.30.10
sudo mv /tmp/docker-compose.yml /data/compose/7/
sudo mkdir -p /data/compose/7/data
cd /data/compose/7
docker compose up -d
```

**Option B: Using Portainer**

1. Go to Portainer in your browser
2. Click "Stacks"
3. Click "Add Stack"
4. Name it "policy-tracker"
5. Paste the content from `docker-compose.yml` (included in the package)
6. Click "Deploy the stack"

### 3. Access and Configure

1. Open browser: http://192.168.1.30:5000
2. Login with: `admin@policytracker.local` / `admin`
3. Go to Account Settings and change your password
4. Go to Account Settings and update email to your real email
5. Go to Settings and set your currency
6. Add your policies!

## New Features Guide

### Adding Policies

- **Friendly Name**: e.g., "Home Mortgage", "Car Insurance - Volvo"
- **Category**: Choose from existing or add new categories
- **Monthly/Annual**: Enter one, the other calculates automatically
- **Notes**: Add any additional information

### Managing Categories

- Go to Categories page
- Add new categories for your needs
- Delete categories (won't delete policies)
- Filter policies by category on main page

### User Management (Admin Only)

- Add new users with email/password
- Toggle admin status for any user
- Enable/disable user accounts
- Delete users (except yourself and last admin)

### Account Settings

- Update your email address
- Change your password
- Simple, single-page settings

## Troubleshooting

**If you get database errors:**
```bash
sudo rm /data/compose/7/data/policies.db
docker restart policy-tracker
```

**If container won't start:**
```bash
docker logs policy-tracker
```

**If you need to force update from GitHub:**
```bash
docker restart policy-tracker
```

The container pulls fresh code from GitHub on every restart!
