import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devsecops-hybrid-sast-key-3.11")

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
ALLOWED_EXTENSIONS = {"zip", "tar", "gz", "py", "js", "ts", "json", "yaml", "yml", "php", "java", "go", "cs"}

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def clean_directories():
    """Clear workspace folders before starting a new scan run."""
    for folder in [UPLOAD_DIR, OUTPUT_DIR]:
        for item in folder.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "target_file" not in request.files:
        flash("No file part detected in request.", "error")
        return redirect(url_for("index"))

    file = request.files["target_file"]
    if file.filename == "":
        flash("No file was selected for upload.", "error")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Unsupported file format. Please upload source files or a .zip archive.", "error")
        return redirect(url_for("index"))

    clean_directories()

    filename = secure_filename(file.filename)
    saved_path = UPLOAD_DIR / filename
    file.save(saved_path)

    # Decompress archive if zip was uploaded
    if filename.endswith(".zip"):
        extract_path = UPLOAD_DIR / "extracted"
        extract_path.mkdir(exist_ok=True)
        with zipfile.ZipFile(saved_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        scan_target = str(extract_path)
    else:
        scan_target = str(saved_path)

    trivy_report_path = OUTPUT_DIR / "trivy-report.json"
    markdown_report_path = OUTPUT_DIR / "SECURITY_REPORT.md"
    pdf_report_path = OUTPUT_DIR / "SECURITY_REPORT.pdf"

    try:
        # Step 1: Run Aqua Security Trivy Scan
        trivy_cmd = [
            "trivy",
            "fs",
            "--security-checks", "vuln,config,secret",
            "--format", "json",
            "--output", str(trivy_report_path),
            scan_target
        ]
        subprocess.run(trivy_cmd, check=True, capture_output=True, text=True)

        # Step 2: Configure Environment for Local Ollama / OpenCode Orchestration
        env = os.environ.copy()
        env["OPENAI_API_BASE"] = "http://localhost:11434/v1"
        env["OPENAI_API_KEY"] = "ollama"

        # Step 3: Run OpenCode AI Agent with local Qwen2.5-Coder model
        opencode_prompt = (
            "Execute the custom sast command: read outputs/trivy-report.json, cross-reference against "
            "files in uploads/, filter false positives, formulate patches, and write the full Marp "
            "presentation to outputs/SECURITY_REPORT.md."
        )
        opencode_cmd = [
            "opencode",
            "run",
            "--model", "qwen2.5-coder:7b",
            opencode_prompt
        ]
        subprocess.run(opencode_cmd, env=env, check=True, capture_output=True, text=True, cwd=str(BASE_DIR))

        # Fallback safeguard: verify report generation
        if not markdown_report_path.exists():
            raise FileNotFoundError("OpenCode did not produce outputs/SECURITY_REPORT.md")

        # Step 4: Convert Markdown Report to Executive PDF using Marp CLI
        marp_cmd = [
            "npx",
            "@marp-team/marp-cli",
            str(markdown_report_path),
            "--pdf",
            "--allow-local-files",
            "-o", str(pdf_report_path)
        ]
        subprocess.run(marp_cmd, check=True, capture_output=True, text=True)

        if not pdf_report_path.exists():
            raise FileNotFoundError("Marp CLI failed to compile outputs/SECURITY_REPORT.pdf")

        return send_file(
            pdf_report_path,
            as_attachment=True,
            download_name="SECURITY_REPORT.pdf",
            mimetype="application/pdf"
        )

    except subprocess.CalledProcessError as err:
        error_msg = err.stderr or err.stdout or str(err)
        flash(f"Pipeline Execution Failure: {error_msg}", "error")
        return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Internal Orchestration Error: {str(exc)}", "error")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
