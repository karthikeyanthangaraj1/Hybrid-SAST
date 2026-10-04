# Hybrid SAST Web Platform (Codespaces / DevContainers)

A self-hosted, cloud-native Static Application Security Testing (SAST) platform engineered to run completely inside **GitHub Codespaces** or any Docker-backed **DevContainer**.

## Architectural Highlights
- **Scanner**: Aqua Security Trivy (CVEs, hardcoded secrets, misconfigurations, and software composition).
- **Local Neural Engine**: Ollama serving `qwen2.5-coder:7b` completely offline inside the DevContainer.
- **Agent Orchestrator**: OpenCode CLI for false-positive context reduction, OWASP/CVSS grouping, and generating actionable code diff patches.
- **Reporting Engine**: Marp CLI generating executive-ready presentation slide PDFs.
- **Interface**: Modern Flask web application featuring drag-and-drop ingestion and automated report downloads.

---

## Quickstart on GitHub Codespaces

1. **Push this repository** to GitHub:
   ```bash
   git init
   git add .
   git commit -m "feat: hybrid SAST platform with local AI & Marp PDF generation"
   git branch -M main
   git remote add origin <YOUR_GITHUB_REPO_URL>
   git push -u origin main
   ```
2. Navigate to your repository on GitHub.
3. Click **Code** -> **Codespaces** -> **Create codespace on main**.
4. GitHub Codespaces detects `.devcontainer/devcontainer.json` and runs `devcontainer-setup.sh`:
   - Installs Aqua Trivy.
   - Installs OpenCode CLI and Marp CLI globally.
   - Installs Ollama daemon and pulls `qwen2.5-coder:7b`.
   - Installs Python dependencies.
5. Once the build finishes, start the platform inside the Codespace terminal:
   ```bash
   python app.py
   ```
6. Port `5000` forwards automatically. Click **Open in Browser** in the port notification, upload your repository or source archive, and retrieve `SECURITY_REPORT.pdf`.
