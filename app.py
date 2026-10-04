import os
import io
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

    # Auto-provision trivy if not found in PATH or standard paths
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

def run_ai_analysis(workspace_dir: Path, trivy_report_path: Path, output_md_path: Path):
    """
    Analyzes Trivy findings using local Qwen2.5-Coder via Ollama HTTP API,
    falling back to OpenCode CLI if direct endpoint is unavailable.
    """
    try:
        with open(trivy_report_path, "r", encoding="utf-8") as f:
            trivy_json = json.load(f)

        prompt = f"""
You are an expert Principal DevSecOps Architect.
Analyze the following Aqua Trivy security scan results for the target {workspace_dir.name}.
1. Validate real vulnerabilities, filter out false positives, and demote unreachable dependencies.
2. Group confirmed findings by OWASP Top 10 and CVSS severity (Critical, High, Medium, Low).
3. Provide exact code remediation unified git diff patches for confirmed issues.
4. Output the complete report formatted in Marp slide presentation Markdown (theme: uncover, paginate: true).

Trivy Results:
{json.dumps(trivy_json, indent=2)[:15000]}
"""
        req_data = json.dumps({
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False
        }).encode("utf-8")

        ollama_req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=req_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(ollama_req, timeout=180) as resp:
            resp_obj = json.loads(resp.read().decode("utf-8"))
            raw_md = resp_obj.get("response", "")
            if not raw_md.strip().startswith("---"):
                raw_md = f"---\nmarp: true\ntheme: uncover\npaginate: true\nheader: 'Hybrid SAST Security Report'\nfooter: 'Aqua Trivy + Qwen2.5-Coder'\n---\n\n{raw_md}"
            output_md_path.write_text(raw_md, encoding="utf-8")
            return
    except Exception:
        pass

    # Fallback to OpenCode CLI
    env = os.environ.copy()
    env["OPENAI_API_BASE"] = "http://localhost:11434/v1"
    env["OPENAI_API_KEY"] = "ollama"
    npx_bin = resolve_binary("npx", ["/usr/local/bin/npx", "/usr/bin/npx"])
    opencode_prompt = (
        "Execute sast: read outputs/trivy-report.json, cross-reference against "
        f"{workspace_dir}, filter false positives, generate diff patches, and write outputs/SECURITY_REPORT.md."
    )
    if shutil.which("opencode") and not shutil.which("opencode").startswith("/root"):
        opencode_cmd = ["opencode", "run", "--model", "qwen2.5-coder:7b", opencode_prompt]
    elif Path("/usr/local/bin/opencode").is_file() and os.access("/usr/local/bin/opencode", os.X_OK):
        opencode_cmd = ["/usr/local/bin/opencode", "run", "--model", "qwen2.5-coder:7b", opencode_prompt]
    else:
        opencode_cmd = [npx_bin, "--yes", "opencode-ai", "run", "--model", "qwen2.5-coder:7b", opencode_prompt]

    subprocess.run(opencode_cmd, env=env, check=True, capture_output=True, text=True, cwd=str(BASE_DIR))

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

        # 3. Execute Aqua Security Trivy Scan
        trivy_cmd = [
            trivy_bin,
            "fs",
            "--security-checks", "vuln,config,secret",
            "--format", "json",
            "--output", str(trivy_report_path),
            str(scan_workspace)
        ]
        subprocess.run(trivy_cmd, check=True, capture_output=True, text=True)

        shutil.copy2(trivy_report_path, global_trivy_report)

        # 4. Execute AI Analysis (Direct Ollama API with OpenCode CLI fallback)
        run_ai_analysis(scan_workspace, trivy_report_path, markdown_report_path)

        if not markdown_report_path.exists():
            raise FileNotFoundError("AI security report (outputs/SECURITY_REPORT.md) was not produced.")

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
        error_msg = err.stderr or err.stdout or str(err)
        if is_json_request:
            return jsonify({"error": f"Pipeline Step Failed: {error_msg}"}), 500
        flash(f"Pipeline Step Failed: {error_msg}", "error")
        return redirect(url_for("index"))
    except Exception as exc:
        if is_json_request:
            return jsonify({"error": f"Audit Orchestration Error: {str(exc)}"}), 500
        flash(f"Audit Orchestration Error: {str(exc)}", "error")
        return redirect(url_for("index"))
    finally:
        # Guaranteed cleanup of raw uploads, workspaces, and temporary execution files
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
