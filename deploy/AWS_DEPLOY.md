# GAGMA — AWS Deployment Guide

## Prerequisites
- AWS account with $50 credit
- SSH key pair (create in AWS Console → EC2 → Key Pairs)

## Step 1: Launch EC2 Instance

1. Go to **AWS Console → EC2 → Launch Instance**
2. Settings:
   - **Name:** GAGMA-Server
   - **AMI:** Ubuntu Server 26.04 LTS (Free tier eligible)
   - **Instance type:** t3.small (2 vCPU, 2GB RAM) — ~$15/month
   - **Key pair:** Select your SSH key
   - **Security Group:** Create new with these rules:
     - SSH (22) — Your IP only
     - HTTP (80) — Anywhere (0.0.0.0/0)
     - HTTPS (443) — Anywhere (0.0.0.0/0)
   - **Storage:** 20 GB gp3
3. Click **Launch Instance**

## Step 2: Connect & Deploy

```bash
# SSH into your instance
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP

# Install git
sudo apt-get update && sudo apt-get install -y git

# Clone your repo (push to GitHub first)
git clone https://github.com/YOUR_USERNAME/gagma.git
cd gagma

# Create .env file with your API keys
cat > .env << 'EOF'
GEMINI_API_KEY=your-gemini-key
VIRUSTOTAL_API_KEY=your-virustotal-key
NEO4J_URI=neo4j+s://40116573.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-neo4j-password
CORS_ORIGINS=http://YOUR_EC2_IP,https://YOUR_EC2_IP
EOF

# Run the deployment script
chmod +x deploy/setup.sh
./deploy/setup.sh
```

## Step 3: Verify

Open browser: `http://YOUR_EC2_PUBLIC_IP`

GAGMA should be live.

## Cost Breakdown

| Service | Monthly Cost |
|---------|-------------|
| EC2 t3.small | $15.00 |
| EBS 20GB gp3 | $1.60 |
| Data transfer (est.) | $1.00 |
| **Total** | **~$18/month** |
| **$50 credit lasts** | **~2.7 months** |

## Optional: Add Domain Later

1. Buy domain (~$10/year) from Namecheap/GoDaddy
2. Point A record to EC2 Elastic IP
3. Edit `deploy/Caddyfile` — uncomment domain block, add your domain
4. `sudo docker compose restart caddy`
5. Caddy auto-provisions HTTPS via Let's Encrypt
