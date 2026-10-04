#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo " Starting Hybrid SAST Platform DevContainer Setup "
echo "=================================================="

# 1. Update system packages and install prerequisites
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
    wget \
    apt-transport-https \
    gnupg \
    lsb-release \
    curl \
    unzip \
    ca-certificates

# 2. Install Aqua Security Trivy via official deb repository
echo "[+] Installing Aqua Security Trivy..."
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update -y
sudo apt-get install -y trivy

# 3. Install OpenCode CLI and Marp CLI globally via npm
echo "[+] Installing OpenCode CLI and Marp CLI..."
sudo npm install -g opencode-ai @marp-team/marp-cli

# 4. Install Python dependencies
echo "[+] Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

# 5. Install and launch Ollama
echo "[+] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

echo "[+] Starting Ollama service daemon..."
# Start Ollama daemon in the background
nohup ollama serve > /tmp/ollama.log 2>&1 &

# Wait for Ollama service to become healthy
echo "[+] Waiting for Ollama engine to be responsive..."
until curl -s http://localhost:11434/api/tags > /dev/null; do
    sleep 2
done

# Pull Qwen 2.5 Coder 7B model
echo "[+] Pulling qwen2.5-coder:7b model into local storage..."
ollama pull qwen2.5-coder:7b

# Create necessary working directories
mkdir -p uploads outputs

echo "=================================================="
echo " Setup complete! Launch app via: python app.py    "
echo "=================================================="
