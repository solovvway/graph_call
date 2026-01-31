#!/usr/bin/env python3
"""
K8s Job entrypoint: SCAN_ID, REPO_ZIP_URL, RABBITMQ_URL from env.
Sends status messages to RabbitMQ queue SCAN_ID, runs scan, uploads reports to MinIO,
sends final result to queue "out".
"""
import os
import sys
import json
import zipfile
import tempfile
import re
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# When run as container entrypoint, run_scan.py is in /app with llm_aditor_prod_core1.py -> APP_ROOT=/app.
# When run from repo root, run_scan.py is in k8s-sast-job/ -> APP_ROOT=repo root (parent).
SCRIPT_DIR = Path(__file__).resolve().parent
APP_ROOT = SCRIPT_DIR if (SCRIPT_DIR / "llm_aditor_prod_core1.py").exists() else SCRIPT_DIR.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))


def send_status(ch, scan_id: str, status: str):
    """Publish status message to queue named scan_id. Queue must be declared by caller."""
    body = json.dumps({"id": scan_id, "from": "SAST", "status": status})
    ch.basic_publish(
        exchange="", routing_key=scan_id, body=body,
        properties=pika.BasicProperties(content_type="application/json", delivery_mode=2)
    )
    logger.info("Sent status: %s", status)


def send_final_result(ch, scan_id: str, vulns: list):
    """Declare 'out' queue and publish ScanResult."""
    ch.queue_declare(queue="out", durable=True)
    body = json.dumps({"id": scan_id, "vulns": vulns})
    ch.basic_publish(
        exchange="", routing_key="out", body=body,
        properties=pika.BasicProperties(content_type="application/json", delivery_mode=2)
    )
    logger.info("Sent final result to out queue: %d vulns", len(vulns))


def _file_from_trace(repo_dir: Path, trace_id: int) -> str:
    """Extract first file path from trace_id_code.txt (location: "path:line")."""
    code_file = repo_dir / f"{trace_id}_code.txt"
    if not code_file.exists():
        return "unknown"
    try:
        text = code_file.read_text(encoding="utf-8", errors="ignore")
        # Match location: "path:line" or location: path:line
        m = re.search(r'location:\s*["\']?([^"\':\s]+(?::\d+)?)', text)
        if m:
            return m.group(1).strip()
        # Fallback: first line that looks like path
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("location:"):
                rest = line[len("location:"):].strip().strip('"\'')
                if rest and not rest.startswith("<"):
                    return rest.split(":")[0] or "unknown"
    except Exception:
        pass
    return "unknown"


def collect_vulns_from_reports(reports_dir: Path, repo_name: str) -> list:
    """Build list of {name, severity, file} from *_report.json with vulnerability=true."""
    repo_dir = reports_dir / repo_name
    if not repo_dir.is_dir():
        return []
    vulns = []
    for f in repo_dir.glob("*_report.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            if not data.get("vulnerability"):
                continue
            trace_id = int(f.stem.replace("_report", ""))
            name = (data.get("reasoning") or data.get("exploit") or "Vulnerability")[:500]
            severity = data.get("confidence", "Medium")
            if severity and isinstance(severity, str):
                severity = severity.capitalize()
            else:
                severity = "Medium"
            file_path = _file_from_trace(repo_dir, trace_id)
            vulns.append({"name": name, "severity": severity, "file": file_path})
        except Exception as e:
            logger.warning("Skip report %s: %s", f, e)
    return vulns


def download_and_extract_repo(url: str, repos_base: Path) -> str:
    """Download zip from url, extract to repos_base. Returns top-level folder name (repo name)."""
    try:
        import requests
    except ImportError:
        raise ImportError("pip install requests")
    logger.info("Downloading repo from %s...", url)
    r = requests.get(url, timeout=300)
    r.raise_for_status()
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(r.content)
        zip_path = f.name
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            names = z.namelist()
            top = names[0].split("/")[0] if names else "repo"
            z.extractall(repos_base)
        return top
    finally:
        Path(zip_path).unlink(missing_ok=True)


def run_analysis(repos_path: Path, reports_dir: Path, config_path: Path, gen_sources: bool):
    """Run prod_core1 orchestrator (sync sources + async trace eval)."""
    import asyncio
    # Patch config on disk so repos_path and reports_dir are correct
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["repos_path"] = str(repos_path)
    config["reports_dir"] = str(reports_dir)
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False))

    sys.argv = ["llm_aditor_prod_core1.py", "--config", str(config_path), "--upload-minio"]
    if gen_sources:
        sys.argv.append("--gen-sources")
    os.chdir(APP_ROOT)
    from llm_aditor_prod_core1 import async_main
    asyncio.run(async_main())


def main():
    scan_id = os.environ.get("SCAN_ID")
    repo_zip_url = os.environ.get("REPO_ZIP_URL")
    rabbitmq_url = os.environ.get("RABBITMQ_URL")
    config_path = os.environ.get("CONFIG_PATH", str(APP_ROOT / "config.json"))

    if not scan_id:
        logger.error("SCAN_ID environment variable is required")
        sys.exit(1)
    if not repo_zip_url:
        logger.error("REPO_ZIP_URL environment variable is required")
        sys.exit(1)
    if not rabbitmq_url:
        logger.error("RABBITMQ_URL environment variable is required")
        sys.exit(1)

    if pika is None:
        logger.error("pika required: pip install pika")
        sys.exit(1)

    logger.info("SAST job started for scan: %s", scan_id)

    work_dir = APP_ROOT
    repos_base = work_dir / "repos"
    reports_dir = work_dir / "reports"
    repos_base.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    config_path = Path(config_path)
    if not config_path.is_absolute():
        config_path = work_dir / config_path
    if not config_path.exists():
        logger.error("Config not found: %s", config_path)
        sys.exit(1)

    conn = pika.BlockingConnection(pika.URLParameters(rabbitmq_url))
    ch = conn.channel()
    ch.queue_declare(queue=scan_id, durable=True)

    try:
        send_status(ch, scan_id, "Scan started")
        conn.process_data_events(time_limit=0)

        repo_name = download_and_extract_repo(repo_zip_url, repos_base)
        send_status(ch, scan_id, f"Downloaded repo {repo_name}")
        conn.process_data_events(time_limit=0)

        send_status(ch, scan_id, "Analyzing repository...")
        run_analysis(repos_base, reports_dir, config_path, gen_sources=os.environ.get("GEN_SOURCES", "").lower() in ("1", "true", "yes"))

        send_status(ch, scan_id, "Uploading reports to MinIO...")
        conn.process_data_events(time_limit=0)
        # MinIO upload is done inside run_analysis (--upload-minio)

        vulns = collect_vulns_from_reports(reports_dir, repo_name)
        send_final_result(ch, scan_id, vulns)
        send_status(ch, scan_id, "Scan completed")
    finally:
        conn.close()

    logger.info("SAST job completed for scan: %s", scan_id)


if __name__ == "__main__":
    main()
