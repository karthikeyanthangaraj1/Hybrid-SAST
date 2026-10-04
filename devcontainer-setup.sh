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
    tar \
    gzip \
    ca-certificates

# 2. Install Aqua Security Trivy via official deb repository
echo "[+] Installing Aqua Security Trivy..."
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update -y
sudo apt-get install -y trivy

# 3. Configure NPM global prefix in /usr/local and install CLI tools
echo "[+] Configuring global NPM directory in /usr/local..."
sudo npm config -g set prefix /usr/local
sudo npm install -g opencode-ai @marp-team/marp-cli

# Set open read & execute permissions for non-root users (like vscode)
sudo chmod -R 755 /usr/local/bin /usr/local/lib/node_modules

# Create symlinks in /usr/bin to guarantee PATH availability
sudo ln -sf /usr/local/bin/opencode /usr/bin/opencode || true
sudo ln -sf /usr/local/bin/marp /usr/bin/marp || true

# If previous root npm directory exists, loosen permissions
if [ -d "/root/.npm-global" ]; then
    sudo chmod 755 /root || true
    sudo chmod -R 755 /root/.npm-global || true
fi

# 4. Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# 5. Install Ollama and pull local model
echo "[+] Installing Ollama engine..."
curl -fsSL https://ollama.com/install.sh | sh

echo "[+] Starting Ollama service daemon..."
nohup ollama serve > /tmp/ollama.log 2>&1 &

echo "[+] Waiting for Ollama engine to become responsive..."
until curl -s http://localhost:11434/api/tags > /dev/null; do
    sleep 2
done

echo "[+] Pulling qwen2.5-coder:7b model locally..."
ollama pull qwen2.5-coder:7b

# Create core working directories
mkdir -p uploads outputs

echo "=================================================="
echo " Setup complete! Launch app via: python app.py    "
echo "=================================================="
