#!/usr/bin/env bash
set -euo pipefail

# BRY-NFET-SX deployment to Digital Ocean droplet
# Usage: ./deploy/deploy.sh
#
# Prerequisites:
#   1. Point DNS: secure.imagineqira.com -> 198.211.100.37
#   2. SSH access to the droplet as root

SERVER="198.211.100.37"
SSH_USER="root"
REMOTE_DIR="/opt/bry-nfet-sx"
DOMAIN="secure.imagineqira.com"

echo "=== BRY-NFET-SX Deploy ==="
echo "  Server:  $SERVER"
echo "  Domain:  $DOMAIN"
echo "  Remote:  $REMOTE_DIR"
echo ""

# Step 1: Ensure Docker is installed on the droplet
echo "[1/5] Checking Docker on remote..."
ssh "$SSH_USER@$SERVER" 'command -v docker >/dev/null 2>&1 || {
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
}'

ssh "$SSH_USER@$SERVER" 'command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 || {
  echo "Installing Docker Compose plugin..."
  apt-get update -qq && apt-get install -y -qq docker-compose-plugin
}'

# Step 2: Create remote directory
echo "[2/5] Preparing remote directory..."
ssh "$SSH_USER@$SERVER" "mkdir -p $REMOTE_DIR"

# Step 3: Sync project files
echo "[3/5] Syncing project files..."
rsync -avz --delete \
  --exclude '.venv' \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude 'data/runs' \
  --exclude 'data/bundles' \
  --exclude 'data/index' \
  --exclude 'data/review' \
  --exclude '.pytest_cache' \
  --exclude '*.pyc' \
  ./ "$SSH_USER@$SERVER:$REMOTE_DIR/"

# Step 4: Build and start
echo "[4/5] Building and starting services..."
ssh "$SSH_USER@$SERVER" "cd $REMOTE_DIR/deploy && docker compose up -d --build"

# Step 5: Verify
echo "[5/5] Waiting for services to start..."
sleep 10

echo ""
echo "=== Deploy complete ==="
echo ""
echo "  Dashboard: https://$DOMAIN"
echo "  API:       https://$DOMAIN/api/health"
echo "  API docs:  https://$DOMAIN/docs"
echo ""
echo "  IMPORTANT: Make sure DNS is configured:"
echo "    secure.imagineqira.com -> $SERVER"
echo ""
echo "  Check logs:"
echo "    ssh $SSH_USER@$SERVER 'cd $REMOTE_DIR/deploy && docker compose logs -f'"
echo ""
