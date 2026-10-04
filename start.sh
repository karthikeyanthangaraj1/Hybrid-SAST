#!/usr/bin/env bash
set -euo pipefail

echo "======================================="
echo " Hybrid SAST Platform — Quick Start    "
echo "======================================="

# ── Resolve python/pip/npm regardless of PATH quirks ──
PYTHON_BIN=""
for p in python3 python /usr/bin/python3 /usr/local/bin/python3; do
    if command -v "$p" &>/dev/null; then PYTHON_BIN="$p"; break; fi
done
if [ -z "$PYTHON_BIN" ]; then echo "[!] Python not found. Aborting."; exit 1; fi
echo "[+] Using Python: $PYTHON_BIN"

NPM_BIN=""
for n in npm /usr/local/bin/npm /usr/bin/npm; do
    if command -v "$n" &>/dev/null; then NPM_BIN="$n"; break; fi
done

# ── 1. Install Trivy if missing ──
if ! command -v trivy &>/dev/null && [ ! -x /usr/local/bin/trivy ]; then
    echo "[+] Installing Aqua Security Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
else
    echo "[✓] Trivy already installed: $(trivy --version 2>/dev/null || echo 'ok')"
fi

# ── 2. Install npm packages (Marp CLI) if npm is available ──
if [ -n "$NPM_BIN" ]; then
    if ! command -v marp &>/dev/null && [ ! -x /usr/local/bin/marp ]; then
        echo "[+] Installing Marp CLI via npm..."
        sudo env "PATH=$PATH" "$NPM_BIN" install -g @marp-team/marp-cli 2>/dev/null || \
            "$NPM_BIN" install -g @marp-team/marp-cli 2>/dev/null || true
        sudo chmod -R 755 /usr/local/bin /usr/local/lib/node_modules 2>/dev/null || true
    else
        echo "[✓] Marp CLI already installed."
    fi
else
    echo "[!] npm not found — Marp will be invoked via npx at scan time."
fi

# ── 3. Install Python dependencies ──
echo "[+] Installing Python requirements..."
"$PYTHON_BIN" -m pip install --upgrade pip 2>/dev/null || true
"$PYTHON_BIN" -m pip install -r requirements.txt

# ── 4. Install & start Ollama if missing ──
if ! command -v zstd &>/dev/null; then
    echo "[+] Installing zstd..."
    sudo apt-get update -y && sudo apt-get install -y zstd 2>/dev/null || true
fi

if ! command -v ollama &>/dev/null; then
    echo "[+] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo "[+] Starting Ollama daemon..."
    nohup ollama serve > /tmp/ollama.log 2>&1 &
    echo "[+] Waiting for Ollama to be ready..."
    until curl -s http://localhost:11434/api/tags &>/dev/null; do sleep 2; done
fi

# Pull model if not already cached
if ! ollama list 2>/dev/null | grep -q "qwen2.5-coder"; then
    echo "[+] Pulling qwen2.5-coder:7b model..."
    ollama pull qwen2.5-coder:7b
else
    echo "[✓] qwen2.5-coder:7b model already cached."
fi

# ── 5. Pull latest code & launch Flask ──
echo "[+] Pulling latest code from origin..."
git pull origin main 2>/dev/null || true

mkdir -p uploads outputs

echo "======================================="
echo " Starting Flask on http://0.0.0.0:5000 "
echo "======================================="
"$PYTHON_BIN" app.py
