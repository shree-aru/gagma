#!/bin/bash
# ─────────────────────────────────────────────────────────
# GAGMA AWS Deployment Script
# Run this on a fresh EC2 Ubuntu 22.04 instance
#
# Usage:
#   1. SSH into your EC2 instance
#   2. git clone your-repo gagma
#   3. cd gagma
#   4. chmod +x deploy/setup.sh
#   5. ./deploy/setup.sh
# ─────────────────────────────────────────────────────────

set -e

echo "============================================"
echo "  GAGMA — Enterprise Deployment Setup"
echo "============================================"

# 1. Update system
echo "[1/5] Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# 2. Install Docker
echo "[2/5] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo "  Docker installed. You may need to log out and back in."
else
    echo "  Docker already installed."
fi

# 3. Install Docker Compose
echo "[3/5] Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    sudo apt-get install -y docker-compose-plugin
fi

# 4. Set up environment
echo "[4/5] Checking .env file..."
if [ ! -f .env ]; then
    echo "  ERROR: .env file not found!"
    echo "  Create .env with your API keys:"
    echo "    GEMINI_API_KEY=your-key-here"
    echo "    VIRUSTOTAL_API_KEY=your-key-here"
    echo "    NEO4J_URI=neo4j+s://your-instance.neo4j.io"
    echo "    NEO4J_USER=neo4j"
    echo "    NEO4J_PASSWORD=your-password"
    exit 1
fi
echo "  .env file found."

# 5. Build and start
echo "[5/5] Building and starting GAGMA..."
sudo docker compose up -d --build

echo ""
echo "============================================"
echo "  GAGMA is now running!"
echo "============================================"
echo ""
echo "  Local:   http://localhost:80"
echo "  Public:  http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'YOUR_EC2_IP')"
echo ""
echo "  Logs:    sudo docker compose logs -f"
echo "  Stop:    sudo docker compose down"
echo "  Restart: sudo docker compose restart"
echo ""
echo "  Health:  curl http://localhost:80/health"
echo ""
