import os
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to JSON config file for LLM settings")
    parser.add_argument("--repos-dir", default="repos", help="Directory where repositories are downloaded")
    parser.add_argument("--reports-dir", default="reports", help="Directory to save reports")
    parser.add_argument("--enable-js", action="store_true", help="Enable analysis of JavaScript/TypeScript files")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # 1. Download repositories
    print("Step 1: Downloading repositories...")
    try:
        subprocess.run(["python3", "downloader.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error downloading repositories: {e}")
        return

    repos_path = Path(args.repos_dir).resolve()
    if not repos_path.exists():
        print(f"Repositories directory not found: {repos_path}")
        return

    # 2. Run llm_auditor on each repository
    print("\nStep 2: Running LLM Auditor on repositories...")
    
    # Get list of directories in repos_dir
    repo_dirs = [d for d in repos_path.iterdir() if d.is_dir()]
    
    if not repo_dirs:
        print("No repositories found to analyze.")
        return

    for repo_dir in repo_dirs:
        print(f"\nAnalyzing {repo_dir.name}...")
        
        cmd = [
            "python3", "llm_auditor.py",
            "--repo", str(repo_dir),
            "--reports", args.reports_dir,
            "--out", args.reports_dir,
            "--config", args.config
        ]
        
        if args.enable_js:
            cmd.append("--enable-js")
            
        if args.debug:
            cmd.append("--debug")
            
        try:
            subprocess.run(cmd, check=True)
            print(f"Finished analyzing {repo_dir.name}")
        except subprocess.CalledProcessError as e:
            print(f"Error analyzing {repo_dir.name}: {e}")
            # Continue with next repo instead of stopping
            continue

    print("\nAll tasks completed.")

if __name__ == "__main__":
    main()