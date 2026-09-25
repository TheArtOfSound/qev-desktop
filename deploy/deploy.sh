#!/usr/bin/env bash
set -euo pipefail

# BRY-NFET-SX deployment to Digital Ocean droplet
# Usage: ./deploy/deploy.sh
#
# Prerequisites:
#   1. Point DNS: secure.imagineqira.com -> 198.211.100.37
#   2. SSH access to the droplet as root

# 2026-07-30: this script targeted 198.211.100.37, a DigitalOcean droplet.
# secure.imagineqira.com has since moved to AWS and now resolves to
# 52.72.26.109 (ec2-52-72-26-109.compute-1.amazonaws.com). Ports 22, 80 and
# 443 are all closed on the old droplet, so running this as it stood would
# have deployed nothing - or worse, pushed to a stale box while production
# carried on serving something else entirely.
#
# SERVER is now derived from DNS so it cannot drift again, with the old
# value kept only as a tripwire.
DOMAIN="secure.imagineqira.com"
SERVER="${SERVER:-$(dig +short "$DOMAIN" | tail -1)}"
STALE_DROPLET="198.211.100.37"
SSH_USER="${SSH_USER:-root}"
REMOTE_DIR="${REMOTE_DIR:-/opt/bry-nfet-sx}"

if [ -z "$SERVER" ]; then
  echo "ERROR: could not resolve $DOMAIN. Refusing to guess a target." >&2
  exit 1
fi
if [ "$SERVER" = "$STALE_DROPLET" ]; then
  echo "ERROR: $DOMAIN resolves to the retired droplet $STALE_DROPLET." >&2
  echo "       Check DNS before deploying." >&2
  exit 1
fi

# Preflight: refuse to deploy to a host that is not actually serving the
# site. Deploying to the wrong machine is silent - the site keeps working
# and you believe you shipped.
echo "[0/5] Verifying $SERVER is really serving $DOMAIN..."
if ! curl -fsS --max-time 15 --resolve "$DOMAIN:443:$SERVER" "https://$DOMAIN/" -o /dev/null; then
  echo "ERROR: $SERVER did not serve https://$DOMAIN/. Wrong host, or it is down." >&2
  exit 1
fi
if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_USER@$SERVER" true 2>/dev/null; then
  echo "ERROR: no SSH to $SSH_USER@$SERVER." >&2
  echo "       As of 2026-07-30 port 22 was filtered from at least one" >&2
  echo "       developer machine - likely an EC2 security-group rule." >&2
  echo "       Fix access before deploying; do not work around this." >&2
  exit 1
fi

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
