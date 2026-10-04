sudo chmod 755 /root && sudo chmod -R 755 /root/.npm-global 2>/dev/null || true
sudo npm config -g set prefix /usr/local && sudo npm install -g opencode-ai @marp-team/marp-cli && sudo chmod -R 755 /usr/local/bin /usr/local/lib/node_modules
pip install -r requirements.txt
pip install --upgrade pip
git pull origin main
python app.py
