# Hybrid SAST Web Platform (GitHub Codespaces / DevContainers)

A cloud-native, self-hosted Static Application Security Testing (SAST) web application engineered to run entirely inside **GitHub Codespaces** or Docker DevContainers.

---

## Technical Highlights

- **Universal Static Scanner**: [Aqua Security Trivy](https://github.com/aquasecurity/trivy) (Vulnerabilities, CVEs, Secrets, Misconfigurations, Binary and Asset Analysis).
- **Private AI Engine**: [Ollama](https://ollama.com/) running `qwen2.5-coder:7b` locally in the container (zero external API keys, zero cloud egress costs).
- **Agent Orchestrator**: OpenCode CLI running context-aware false-positive deduplication and generating unified git diff patches.
- **Executive PDF Generation**: [Marp CLI](https://marp.app/) (`@marp-team/marp-cli`) transforming audit markdown into presentation slide PDFs.
- **Universal Target Support**: Accepts archives (`.zip`, `.apk`, `.tar.gz`, `.jar`, `.war`) and raw code/binary files (`.exe`, `.php`, `.aspx`, `.py`, `.db`, etc.) via a responsive dark-themed drag-and-drop web UI.

---

## Quickstart Guide for GitHub Codespaces

### 1. Launch Codespace
1. Navigate to your repository on GitHub (`https://github.com/karthikeyanthangaraj1/Hybrid-SAST`).
2. Click the green **Code** button &rarr; select the **Codespaces** tab &rarr; click **Create codespace on main**.
3. GitHub Codespaces will automatically build the container defined in `.devcontainer/devcontainer.json` and execute `devcontainer-setup.sh`:
   - Configures Aqua Trivy via deb repository.
   - Installs OpenCode and Marp CLI globally via npm.
   - Installs Python dependencies (`flask==3.0.3`).
   - Downloads the Ollama engine and pulls `qwen2.5-coder:7b`.

### 2. Start the Platform
In the Codespace integrated terminal, run:
```bash
python app.py
```

### 3. Run Security Audits
1. GitHub Codespaces will detect port `5000` and automatically display a notification: **Open in Browser**.
2. Drag and drop any repository archive (`.zip`, `.apk`, `.tar.gz`) or source file (`.php`, `.py`, `.exe`, etc.).
3. Click **Execute Hybrid SAST Audit**.
4. The pipeline will unpack the asset, run Trivy static checks, invoke Qwen 2.5 Coder to filter false positives and craft remediations, compile the Marp report, and immediately download `SECURITY_REPORT.pdf`.

---

## Repository Structure

```text
my-sast-platform/
├── .devcontainer/
│   └── devcontainer.json      # DevContainer configuration with Node & Python
├── .opencode/
│   └── commands/
│       └── sast.md            # AI orchestrator prompt & Marp report template
├── templates/
│   └── index.html             # Responsive dark UI with format badges
├── app.py                     # Flask backend with universal file unpacker & pipeline runner
├── devcontainer-setup.sh      # Automated provisioning script for tools & Ollama
├── requirements.txt           # Pinned Python requirements (flask==3.0.3)
├── .gitignore                 # Excludes scan artifacts, uploads, and caches
└── README.md                  # Documentation and quickstart guide
```
