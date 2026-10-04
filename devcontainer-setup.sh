#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo " Starting Hybrid SAST Platform DevContainer Setup "
echo "=================================================="

# ── Resolve python/pip/npm with full path discovery ──
PYTHON_BIN=""
for p in python3 python /usr/bin/python3 /usr/local/bin/python3; do
    if command -v "$p" &>/dev/null; then PYTHON_BIN="$p"; break; fi
done
if [ -z "$PYTHON_BIN" ]; then echo "[!] Python not found."; exit 1; fi

NPM_BIN=""
for n in npm /usr/local/bin/npm /usr/bin/npm; do
    if command -v "$n" &>/dev/null; then NPM_BIN="$n"; break; fi
done

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

# 2. Install Aqua Security Trivy via official installer
echo "[+] Installing Aqua Security Trivy..."
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
sudo chmod 755 /usr/local/bin/trivy

# 3. Install npm CLI tools (Marp CLI, OpenCode) if npm is available
if [ -n "$NPM_BIN" ]; then
    echo "[+] Installing Marp CLI and OpenCode CLI via npm..."
    sudo env "PATH=$PATH" "$NPM_BIN" install -g @marp-team/marp-cli opencode-ai 2>/dev/null || \
        "$NPM_BIN" install -g @marp-team/marp-cli opencode-ai 2>/dev/null || true
    sudo chmod -R 755 /usr/local/bin /usr/local/lib/node_modules 2>/dev/null || true
    sudo ln -sf /usr/local/bin/opencode /usr/bin/opencode 2>/dev/null || true
    sudo ln -sf /usr/local/bin/marp /usr/bin/marp 2>/dev/null || true
else
    echo "[!] npm not found — Marp/OpenCode will be invoked via npx at scan time."
fi

# 4. Install Python dependencies
echo "[+] Installing Python dependencies..."
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r requirements.txt

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
