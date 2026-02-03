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
✅ Modern logo integrated throughout
✅ Clean, professional UI

## Deployment Steps

### 1. On Your Mac - Extract and Push to GitHub

```bash
cd ~/Downloads
tar -xzf policy-tracker-full.tar.gz
cd policy-tracker-full

# Initialize git
git init
git add .
git commit -m "Complete Policy Tracker with all features"

# Add remote and push (force to replace everything)
git remote add origin https://github.com/adrianchatto/insurance-tracker.git
git branch -m master main
git push -u origin main --force
```

### 2. On Your Server - Update Docker

SSH to your server:
```bash
ssh adrianchatto@172.22.30.10
```

Update the docker-compose.yml in Portainer or via file:
```bash
sudo nano /data/compose/7/docker-compose.yml
```

Use this docker-compose.yml:
```yaml
version: '3.8'

services:
  policy-tracker:
    image: python:3.11-slim
    container_name: policy-tracker
    command: sh -c "apt-get update && apt-get install -y git &&
       rm -rf /app/code &&
       git clone https://github.com/adrianchatto/insurance-tracker.git /app/code &&
       cd /app/code &&
       pip install --no-cache-dir -r requirements.txt &&
       cp -r /app/code/* /app/ &&
       python app.py"
    ports:
      - "5000:5000"
    volumes:
      - ./data:/app/data
    environment:
      - SECRET_KEY=change-this-to-a-random-secret-key-in-production
      - DB_PATH=/app/data/policies.db
    restart: unless-stopped
    working_dir: /app
```

Create data directory and restart:
```bash
sudo mkdir -p /data/compose/7/data
cd /data/compose/7
docker-compose down
docker-compose up -d
```

### 3. Access and Configure

1. Open browser: http://192.168.1.30:5000
2. Login with: `admin@policytracker.local` / `admin`
3. Go to Account Settings and change your password
4. Go to Account Settings and update email to your real email
5. Add your policies!

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
