import os
import subprocess
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Download and analyze repositories for security vulnerabilities")
    parser.add_argument("--config", required=True, help="Path to JSON config file for LLM settings")
    parser.add_argument("--repos-dir", default="repos", help="Directory where repositories are downloaded (default: repos)")
    parser.add_argument("--reports-dir", default="reports", help="Directory to save reports (default: reports)")
    parser.add_argument("--repo-count", type=int, default=20, help="Number of repositories to download (default: 20)")
    parser.add_argument("--skip-download", action="store_true", help="Skip downloading repositories (use existing repos)")
    parser.add_argument("--enable-js", action="store_true", help="Enable analysis of JavaScript/TypeScript files")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    repos_path = Path(args.repos_dir).resolve()
    
    # 1. Download repositories (unless skipped)
    if not args.skip_download:
        print(f"Step 1: Downloading repositories to {repos_path}...")
        try:
            download_cmd = [
                "python3", "downloader.py",
                "--output-dir", str(repos_path),
                "--count", str(args.repo_count)
            ]
            subprocess.run(download_cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error downloading repositories: {e}")
            return
    else:
        print("Step 1: Skipping download (--skip-download specified)")

    if not repos_path.exists():
        print(f"Repositories directory not found: {repos_path}")
        return

    # 2. Run llm_auditor on each repository
    print(f"\nStep 2: Running LLM Auditor on repositories in {repos_path}...")
    
    # Get list of directories in repos_dir that are git repositories (have .git folder)
    # This ensures we only analyze actual cloned repos, not random directories
    repo_dirs = []
    for d in repos_path.iterdir():
        if d.is_dir():
            # Check if it's a git repository
            if (d / ".git").exists():
                repo_dirs.append(d)
            else:
                print(f"Skipping {d.name} (not a git repository)")
    
    if not repo_dirs:
        print("No git repositories found to analyze.")
        print(f"Make sure repositories are cloned to: {repos_path}")
        return

    print(f"Found {len(repo_dirs)} git repositories to analyze")
    
    for i, repo_dir in enumerate(repo_dirs, 1):
        print(f"\n[{i}/{len(repo_dirs)}] Analyzing {repo_dir.name}...")
        
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