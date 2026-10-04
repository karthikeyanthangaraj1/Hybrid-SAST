import os
import io
import uuid
import shutil
import tarfile
import zipfile
import subprocess
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devsecops-hybrid-sast-key-3.11")

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Archive extensions handled by universal unpacker
ARCHIVE_EXTENSIONS = {".zip", ".apk", ".jar", ".war", ".tar.gz", ".tgz", ".tar"}

def resolve_binary(binary_name: str, fallback_candidates: list[str]) -> str:
    """Dynamically resolves system binary locations to prevent 'No such file or directory' errors."""
    resolved = shutil.which(binary_name)
    if resolved:
        return resolved
    for candidate in fallback_candidates:
        candidate_path = Path(candidate)
        if candidate_path.exists() and os.access(candidate_path, os.X_OK):
            return str(candidate_path)
    return binary_name

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
            # Prevent ZipSlip vulnerability
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
        # Standalone code file, binary, database, or executable
        destination = workspace_dir / saved_file_path.name
        shutil.copy2(saved_file_path, destination)
        return workspace_dir

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "target_file" not in request.files:
        flash("No file payload detected in request.", "error")
        return redirect(url_for("index"))

    file = request.files["target_file"]
    if not file or file.filename == "":
        flash("No file was selected for upload.", "error")
        return redirect(url_for("index"))

    scan_id = uuid.uuid4().hex[:8]
    filename = secure_filename(file.filename) or f"target_asset_{scan_id}"
    saved_upload_path = UPLOAD_DIR / f"{scan_id}_{filename}"
    scan_workspace = UPLOAD_DIR / f"workspace_{scan_id}"
    
    trivy_report_path = OUTPUT_DIR / f"trivy-report-{scan_id}.json"
    global_trivy_report = OUTPUT_DIR / "trivy-report.json"
    markdown_report_path = OUTPUT_DIR / "SECURITY_REPORT.md"
    pdf_report_path = OUTPUT_DIR / f"SECURITY_REPORT_{scan_id}.pdf"

    pdf_stream = None

    try:
        # Save raw upload
        file.save(saved_upload_path)

        # Unpack or place target into dedicated workspace
        prepare_target_directory(saved_upload_path, scan_workspace)

        # 1. Resolve Executable Binaries
        trivy_bin = resolve_binary("trivy", ["/usr/local/bin/trivy", "/usr/bin/trivy"])
        opencode_bin = resolve_binary("opencode", ["/usr/local/bin/opencode", "/usr/bin/opencode", "/root/.npm-global/bin/opencode"])
        npx_bin = resolve_binary("npx", ["/usr/local/bin/npx", "/usr/bin/npx"])

        # 2. Execute Aqua Security Trivy Scan
        trivy_cmd = [
            trivy_bin,
            "fs",
            "--security-checks", "vuln,config,secret",
            "--format", "json",
            "--output", str(trivy_report_path),
            str(scan_workspace)
        ]
        subprocess.run(trivy_cmd, check=True, capture_output=True, text=True)

        # Mirror output to standard trivy-report.json for OpenCode command ingestion
        shutil.copy2(trivy_report_path, global_trivy_report)

        # 3. Configure Local Ollama Environment
        env = os.environ.copy()
        env["OPENAI_API_BASE"] = "http://localhost:11434/v1"
        env["OPENAI_API_KEY"] = "ollama"

        # 4. Execute OpenCode AI Agent with Qwen 2.5 Coder
        opencode_prompt = (
            "Execute the custom sast command: read outputs/trivy-report.json, cross-reference against "
            f"the code in {scan_workspace}, filter false positives, formulate patches, and write the full Marp "
            "presentation to outputs/SECURITY_REPORT.md."
        )
        opencode_cmd = [
            opencode_bin,
            "run",
            "--model", "qwen2.5-coder:7b",
            opencode_prompt
        ]
        subprocess.run(opencode_cmd, env=env, check=True, capture_output=True, text=True, cwd=str(BASE_DIR))

        if not markdown_report_path.exists():
            raise FileNotFoundError("OpenCode AI agent did not produce outputs/SECURITY_REPORT.md")

        # 5. Compile Marp Markdown into Executive PDF
        marp_cmd = [
            npx_bin,
            "@marp-team/marp-cli",
            str(markdown_report_path),
            "--pdf",
            "--allow-local-files",
            "-o", str(pdf_report_path)
        ]
        subprocess.run(marp_cmd, check=True, capture_output=True, text=True)

        if not pdf_report_path.exists():
            raise FileNotFoundError("Marp CLI failed to compile outputs/SECURITY_REPORT.pdf")

        # Buffer PDF in memory for immediate download
        with open(pdf_report_path, "rb") as f:
            pdf_stream = io.BytesIO(f.read())

    except subprocess.CalledProcessError as err:
        error_msg = err.stderr or err.stdout or str(err)
        flash(f"Pipeline Step Failed: {error_msg}", "error")
        return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Audit Orchestration Error: {str(exc)}", "error")
        return redirect(url_for("index"))
    finally:
        # Guaranteed cleanup of raw uploads, workspaces, and temporary execution files
        if saved_upload_path.exists():
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
