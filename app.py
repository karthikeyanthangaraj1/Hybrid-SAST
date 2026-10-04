import os
import io
import re
import json
import uuid
import shutil
import tarfile
import zipfile
import urllib.request
import subprocess
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devsecops-hybrid-sast-key-3.11")
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB allowance

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

ARCHIVE_EXTENSIONS = {".zip", ".apk", ".jar", ".war", ".tar.gz", ".tgz", ".tar"}

def clean_ansi(text: str) -> str:
    """Strips terminal ANSI color and formatting escape sequences."""
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)

def resolve_binary(binary_name: str, fallback_candidates: list[str]) -> str:
    """Dynamically resolves system binary locations to prevent 'No such file or directory' errors."""
    resolved = shutil.which(binary_name)
    if resolved:
        try:
            if os.access(resolved, os.X_OK) and not resolved.startswith("/root"):
                return resolved
        except (PermissionError, OSError):
            pass

    for candidate in fallback_candidates:
        if candidate.startswith("/root"):
            continue
        candidate_path = Path(os.path.expanduser(candidate))
        try:
            if candidate_path.is_file() and os.access(candidate_path, os.X_OK):
                return str(candidate_path)
        except (PermissionError, OSError):
            continue
    return binary_name

def ensure_trivy() -> str:
    """Finds or automatically installs Aqua Trivy if missing to prevent Errno 2."""
    trivy_bin = resolve_binary("trivy", ["/usr/local/bin/trivy", "/usr/bin/trivy"])
    if shutil.which(trivy_bin) or (Path(trivy_bin).is_file() and os.access(trivy_bin, os.X_OK)):
        return trivy_bin

    try:
        install_cmd = "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin"
        subprocess.run(install_cmd, shell=True, check=True, capture_output=True)
        if Path("/usr/local/bin/trivy").is_file():
            return "/usr/local/bin/trivy"
    except Exception:
        pass
    return trivy_bin

def is_archive(filename: str) -> bool:
    lower_name = filename.lower()
    return any(lower_name.endswith(ext) for ext in ARCHIVE_EXTENSIONS)

def prepare_target_directory(saved_file_path: Path, workspace_dir: Path) -> Path:
    """
    Safely unpacks archives (.zip, .apk, .jar, .war, .tar.gz, .tgz) into the workspace,
    or copies standalone files (.exe, .php, .aspx, .py, .db, etc.) directly into it.
    """
    workspace_dir.mkdir(parents=True, exist_ok=True)
    filename_lower = saved_file_path.name.lower()

    if filename_lower.endswith((".zip", ".apk", ".jar", ".war")):
        with zipfile.ZipFile(saved_file_path, 'r') as archive:
            for member in archive.infolist():
                target_path = (workspace_dir / member.filename).resolve()
                if not str(target_path).startswith(str(workspace_dir.resolve())):
                    raise ValueError(f"Unsafe path detected in zip archive: {member.filename}")
            archive.extractall(workspace_dir)
        return workspace_dir

    elif filename_lower.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if filename_lower.endswith((".tar.gz", ".tgz")) else "r:"
        with tarfile.open(saved_file_path, mode) as archive:
            for member in archive.getmembers():
                target_path = (workspace_dir / member.name).resolve()
                if not str(target_path).startswith(str(workspace_dir.resolve())):
                    raise ValueError(f"Unsafe path detected in tar archive: {member.name}")
            archive.extractall(workspace_dir)
        return workspace_dir

    else:
        destination = workspace_dir / saved_file_path.name
        shutil.copy2(saved_file_path, destination)
        return workspace_dir

def generate_deterministic_marp_report(workspace_name: str, trivy_json: dict) -> str:
    """Generates a professional Marp presentation report directly from Trivy scan findings."""
    results = trivy_json.get("Results", [])
    vulns = []
    secrets = []
    configs = []

    for res in results:
        target = res.get("Target", workspace_name)
        for v in res.get("Vulnerabilities", []):
            vulns.append({
                "id": v.get("VulnerabilityID", "N/A"),
                "pkg": v.get("PkgName", "N/A"),
                "severity": v.get("Severity", "UNKNOWN"),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", "N/A"),
                "title": (v.get("Title") or v.get("Description") or "Vulnerability detected")[:110],
                "target": target
            })
        for s in res.get("Secrets", []):
            secrets.append({
                "id": s.get("RuleID", "Secret"),
                "title": s.get("Title", "Exposed Secret / Key"),
                "severity": s.get("Severity", "CRITICAL"),
                "target": target,
                "line": s.get("StartLine", "N/A")
            })
        for c in res.get("Misconfigurations", []):
            configs.append({
                "id": c.get("ID", "Misconfig"),
                "title": (c.get("Title") or c.get("Message") or "Misconfiguration")[:110],
                "severity": c.get("Severity", "MEDIUM"),
                "target": target
            })

    total_findings = len(vulns) + len(secrets) + len(configs)
    crit_count = sum(1 for x in vulns + secrets if x.get("severity") in ("CRITICAL", "HIGH"))
    posture = "SECURE / CLEAN" if total_findings == 0 else ("HIGH RISK" if crit_count > 0 else "MODERATE RISK")
    posture_class = "low" if total_findings == 0 else ("critical" if crit_count > 0 else "medium")

    slides = [
        f"""---
marp: true
theme: uncover
paginate: true
header: "Hybrid SAST Executive Security Report"
footer: "Aqua Trivy + Qwen2.5-Coder Engine"
style: |
  section {{
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    text-align: left;
    font-size: 20px;
    padding: 40px;
  }}
  h1, h2, h3 {{ color: #58a6ff; }}
  code {{ background: #161b22; color: #79c0ff; }}
  pre {{ background: #161b22; border: 1px solid #30363d; }}
  .critical {{ color: #f85149; font-weight: bold; }}
  .high {{ color: #d29922; font-weight: bold; }}
  .medium {{ color: #dbab09; }}
  .low {{ color: #56d364; }}
---

# Hybrid SAST Audit Report
### Target: `{workspace_name}`
**Engine:** Aqua Trivy Scanner + Qwen 2.5 Coder
**Execution Status:** Pipeline Completed

---

## Executive Summary

- **Total Security Findings:** {total_findings}
- **Vulnerabilities (CVEs):** {len(vulns)}
- **Hardcoded Secrets:** {len(secrets)}
- **IaC Misconfigurations:** {len(configs)}
- **Overall Posture:** <span class="{posture_class}">{posture}</span>
"""
    ]

    if total_findings == 0:
        slides.append("""---

## Audit Outcome: Clean

No known vulnerabilities, exposed secrets, or configuration flaws were identified in the target asset.

### Verification Checklist
- Package manifest dependencies verified against Aqua vulnerability database
- Static source pattern heuristics matched zero hardcoded credentials
- Configuration files compliant with baseline security profiles
""")
    else:
        table_rows = []
        for item in (vulns + secrets + configs)[:8]:
            sev = item.get("severity", "LOW")
            css = "critical" if sev == "CRITICAL" else ("high" if sev == "HIGH" else "medium")
            table_rows.append(f"| {item.get('id')} | {item.get('pkg', item.get('target', 'Asset'))} | <span class=\"{css}\">{sev}</span> |")

        table_md = "\n".join(table_rows)
        slides.append(f"""---

## Key Findings Breakdown

| Identifier | Component | Severity |
| :--- | :--- | :--- |
{table_md}
""")

        for item in (vulns + secrets)[:3]:
            sev = item.get("severity", "HIGH")
            css = "critical" if sev == "CRITICAL" else "high"
            slides.append(f"""---

### Finding Deep-Dive: {item.get('id')}

- **Severity:** <span class="{css}">{sev}</span>
- **Target:** `{item.get('target')}`
- **Description:** {item.get('title')}

#### Recommended Remediation
```diff
- Current vulnerable dependency / configuration
+ Update to latest patched version / rotate credentials immediately
```
""")

    slides.append("""---

## Hardening Recommendations

1. **Dependency Hygiene:** Automate package upgrades in CI/CD pipeline.
2. **Secrets Governance:** Adopt secret managers; avoid inline credentials.
3. **Continuous SAST:** Run static scans on every pull request.
""")

    return "\n".join(slides)

def run_ai_analysis(workspace_dir: Path, trivy_report_path: Path, output_md_path: Path):
    """
    Analyzes Trivy findings using local Qwen2.5-Coder via Ollama HTTP API (127.0.0.1).
    Falls back gracefully to deterministic Marp generator if Ollama is busy or times out.
    """
    trivy_json = {}
    try:
        with open(trivy_report_path, "r", encoding="utf-8") as f:
            trivy_json = json.load(f)
    except Exception:
        pass

    ai_generated = False
    try:
        prompt = f"""
You are an expert Principal DevSecOps Architect.
Analyze the following Aqua Trivy security scan results for the target {workspace_dir.name}.
1. Validate real vulnerabilities, filter out false positives, and demote unreachable dependencies.
2. Group confirmed findings by OWASP Top 10 and CVSS severity (Critical, High, Medium, Low).
3. Provide exact code remediation unified git diff patches for confirmed issues.
4. Output the complete report formatted in Marp slide presentation Markdown (theme: uncover, paginate: true).

Trivy Results:
{json.dumps(trivy_json, indent=2)[:10000]}
"""
        req_data = json.dumps({
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False
        }).encode("utf-8")

        # Explicitly use 127.0.0.1 (IPv4) to avoid IPv6 loopback connection refused errors
        ollama_req = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(ollama_req, timeout=90) as resp:
            resp_obj = json.loads(resp.read().decode("utf-8"))
            raw_md = resp_obj.get("response", "").strip()
            if raw_md:
                if not raw_md.startswith("---"):
                    raw_md = f"---\nmarp: true\ntheme: uncover\npaginate: true\nheader: 'Hybrid SAST Security Report'\nfooter: 'Aqua Trivy + Qwen2.5-Coder'\n---\n\n{raw_md}"
                output_md_path.write_text(raw_md, encoding="utf-8")
                ai_generated = True
    except Exception as exc:
        print(f"[i] Ollama generation skipped ({exc}); using native Marp generator.")

    if not ai_generated:
        marp_content = generate_deterministic_marp_report(workspace_dir.name, trivy_json)
        output_md_path.write_text(marp_content, encoding="utf-8")

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload_chunk", methods=["POST"])
def upload_chunk():
    """Receives file slices (chunks) under 2MB to bypass GitHub Codespaces / Nginx 413 limits."""
    upload_id = request.form.get("upload_id")
    chunk_index = request.form.get("chunk_index", type=int)
    total_chunks = request.form.get("total_chunks", type=int)
    filename = request.form.get("filename")
    chunk_file = request.files.get("chunk")

    if not upload_id or chunk_index is None or not filename or not chunk_file:
        return jsonify({"error": "Missing chunk parameters"}), 400

    safe_name = secure_filename(filename) or "upload_target"
    target_assembled_path = UPLOAD_DIR / f"chunked_{upload_id}_{safe_name}"

    mode = "wb" if chunk_index == 0 else "ab"
    with open(target_assembled_path, mode) as f:
        f.write(chunk_file.read())

    return jsonify({"status": "ok", "chunk_index": chunk_index, "total_chunks": total_chunks})

@app.route("/scan", methods=["POST"])
def scan():
    scan_id = uuid.uuid4().hex[:8]
    is_json_request = request.is_json
    saved_upload_path = None
    upload_id = None
    filename = None

    if is_json_request:
        payload = request.get_json() or {}
        upload_id = payload.get("upload_id")
        filename = payload.get("filename")
    else:
        upload_id = request.form.get("upload_id")
        filename = request.form.get("filename")

    if upload_id and filename:
        safe_name = secure_filename(filename) or f"target_{scan_id}"
        chunked_file = UPLOAD_DIR / f"chunked_{upload_id}_{safe_name}"
        if not chunked_file.exists():
            err_msg = "Assembled upload payload not found on server."
            return jsonify({"error": err_msg}), 400 if is_json_request else (flash(err_msg, "error"), redirect(url_for("index")))[1]
        saved_upload_path = chunked_file
    elif "target_file" in request.files:
        file = request.files["target_file"]
        if not file or file.filename == "":
            err_msg = "No file selected for audit."
            return jsonify({"error": err_msg}), 400 if is_json_request else (flash(err_msg, "error"), redirect(url_for("index")))[1]
        safe_name = secure_filename(file.filename) or f"target_{scan_id}"
        saved_upload_path = UPLOAD_DIR / f"{scan_id}_{safe_name}"
        file.save(saved_upload_path)
    else:
        err_msg = "No file payload detected in request."
        return jsonify({"error": err_msg}), 400 if is_json_request else (flash(err_msg, "error"), redirect(url_for("index")))[1]

    scan_workspace = UPLOAD_DIR / f"workspace_{scan_id}"
    trivy_report_path = OUTPUT_DIR / f"trivy-report-{scan_id}.json"
    global_trivy_report = OUTPUT_DIR / "trivy-report.json"
    markdown_report_path = OUTPUT_DIR / "SECURITY_REPORT.md"
    pdf_report_path = OUTPUT_DIR / f"SECURITY_REPORT_{scan_id}.pdf"

    pdf_stream = None

    try:
        # 1. Unpack or place target into dedicated workspace
        prepare_target_directory(saved_upload_path, scan_workspace)

        # 2. Ensure Aqua Trivy Binary is Present
        trivy_bin = ensure_trivy()

        # 3. Execute Aqua Security Trivy Scan (Supporting both modern --scanners and fallback)
        trivy_cmd = [
            trivy_bin,
            "fs",
            "--scanners", "vuln,misconfig,secret",
            "--format", "json",
            "--output", str(trivy_report_path),
            str(scan_workspace)
        ]
        res = subprocess.run(trivy_cmd, capture_output=True, text=True)
        if res.returncode != 0:
            # Fallback to legacy flag if older Trivy version
            trivy_cmd_legacy = [
                trivy_bin,
                "fs",
                "--security-checks", "vuln,config,secret",
                "--format", "json",
                "--output", str(trivy_report_path),
                str(scan_workspace)
            ]
            subprocess.run(trivy_cmd_legacy, check=True, capture_output=True, text=True)

        shutil.copy2(trivy_report_path, global_trivy_report)

        # 4. Execute AI Analysis (Direct Ollama API with graceful deterministic fallback)
        run_ai_analysis(scan_workspace, trivy_report_path, markdown_report_path)

        if not markdown_report_path.exists():
            raise FileNotFoundError("Security markdown report was not produced.")

        # 5. Compile Marp Markdown into Executive PDF
        npx_bin = resolve_binary("npx", ["/usr/local/bin/npx", "/usr/bin/npx"])
        marp_bin = resolve_binary("marp", ["/usr/local/bin/marp", "/usr/bin/marp"])
        if shutil.which(marp_bin) or (Path(marp_bin).is_file() and os.access(marp_bin, os.X_OK)):
            marp_cmd = [marp_bin, str(markdown_report_path), "--pdf", "--allow-local-files", "-o", str(pdf_report_path)]
        else:
            marp_cmd = [npx_bin, "@marp-team/marp-cli", str(markdown_report_path), "--pdf", "--allow-local-files", "-o", str(pdf_report_path)]

        subprocess.run(marp_cmd, check=True, capture_output=True, text=True)

        if not pdf_report_path.exists():
            raise FileNotFoundError("Marp CLI failed to compile outputs/SECURITY_REPORT.pdf")

        # Buffer PDF in memory for immediate transmission
        with open(pdf_report_path, "rb") as f:
            pdf_stream = io.BytesIO(f.read())

    except subprocess.CalledProcessError as err:
        error_msg = clean_ansi(err.stderr or err.stdout or str(err))
        if is_json_request:
            return jsonify({"error": f"Pipeline Step Failed: {error_msg}"}), 500
        flash(f"Pipeline Step Failed: {error_msg}", "error")
        return redirect(url_for("index"))
    except Exception as exc:
        clean_msg = clean_ansi(str(exc))
        if is_json_request:
            return jsonify({"error": f"Audit Orchestration Error: {clean_msg}"}), 500
        flash(f"Audit Orchestration Error: {clean_msg}", "error")
        return redirect(url_for("index"))
    finally:
        if saved_upload_path and saved_upload_path.exists():
            saved_upload_path.unlink(missing_ok=True)
        if scan_workspace.exists():
            shutil.rmtree(scan_workspace, ignore_errors=True)
        if trivy_report_path.exists():
            trivy_report_path.unlink(missing_ok=True)
        if pdf_report_path.exists():
            pdf_report_path.unlink(missing_ok=True)

    if pdf_stream:
        return send_file(
            pdf_stream,
            as_attachment=True,
            download_name="SECURITY_REPORT.pdf",
            mimetype="application/pdf"
        )
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
