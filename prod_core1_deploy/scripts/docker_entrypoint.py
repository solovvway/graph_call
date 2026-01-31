#!/usr/bin/env python3
"""Download repo zip from REPO_ZIP_URL, unzip to repos/, run llm_aditor_prod_core1 with config."""
import os
import sys
import json
import zipfile
import tempfile
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


def main():
    repo_zip_url = os.environ.get("REPO_ZIP_URL")
    config_path = os.environ.get("CONFIG_PATH", "/app/config.json")
    work_dir = Path("/app").resolve()
    repos_base = work_dir / "repos"
    repos_base.mkdir(parents=True, exist_ok=True)

    if repo_zip_url:
        if not requests:
            print("REPO_ZIP_URL set but requests not installed; pip install requests", file=sys.stderr)
            sys.exit(1)
        print(f"Downloading repo from {repo_zip_url}...")
        try:
            r = requests.get(repo_zip_url, timeout=300)
            r.raise_for_status()
        except Exception as e:
            print(f"Download failed: {e}", file=sys.stderr)
            sys.exit(1)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(r.content)
            zip_path = f.name
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                names = z.namelist()
                # Top-level dir name from first entry (e.g. "repo-name/")
                top = names[0].split("/")[0] if names else "repo"
                dest = repos_base / top
                dest.mkdir(parents=True, exist_ok=True)
                z.extractall(repos_base)
            print(f"Extracted to {repos_base}")
        finally:
            Path(zip_path).unlink(missing_ok=True)

    # Ensure config has repos_path pointing to our repos dir
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        config["repos_path"] = str(repos_base)
        config["reports_dir"] = str(work_dir / "reports")
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

    os.chdir(work_dir)
    sys.path.insert(0, str(work_dir))
    sys.argv = ["llm_aditor_prod_core1.py", "--config", config_path]
    from llm_aditor_prod_core1 import main as run_auditor
    run_auditor()


if __name__ == "__main__":
    main()
