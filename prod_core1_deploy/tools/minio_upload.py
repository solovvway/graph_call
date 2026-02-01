#!/usr/bin/env python3
"""Upload report files from reports_dir/repo_name to a MinIO bucket named after the repo."""
import os
import re
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _normalize_bucket_name(repo_name: str) -> str:
    """Normalize repo name for MinIO bucket: lowercase, alphanumeric and hyphens only."""
    s = repo_name.lower().strip()
    s = re.sub(r"[^a-z0-9-]", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "reports"


def upload_reports_to_minio(
    reports_dir: Path,
    repo_name: str,
    *,
    endpoint: Optional[str] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    secure: bool = True,
    bucket_name: Optional[str] = None,
) -> int:
    """
    Create a MinIO bucket named after the repo (normalized) or use provided bucket_name,
    and upload all files from reports_dir/repo_name into it. Object names preserve relative path.

    Args:
        reports_dir: Base reports directory (e.g. reports).
        repo_name: Repository name (subfolder under reports_dir).
        endpoint: MinIO endpoint (host:port). Default: MINIO_ENDPOINT env.
        access_key: MinIO access key. Default: MINIO_ACCESS_KEY env.
        secret_key: MinIO secret key. Default: MINIO_SECRET_KEY env.
        secure: Use HTTPS. Default: MINIO_SECURE env or True.
        bucket_name: Optional explicit bucket name. If not provided, derived from repo_name.

    Returns:
        Number of objects uploaded.
    """
    try:
        from minio import Minio
    except ImportError:
        raise ImportError("minio package required: pip install minio")

    endpoint = endpoint or os.environ.get("MINIO_ENDPOINT")
    access_key = access_key or os.environ.get("MINIO_ACCESS_KEY")
    secret_key = secret_key or os.environ.get("MINIO_SECRET_KEY")
    if os.environ.get("MINIO_SECURE", "true").lower() in ("0", "false", "no"):
        secure = False
    else:
        secure = secure

    if not endpoint or not access_key or not secret_key:
        raise ValueError(
            "MinIO credentials required: set MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY"
        )

    repo_dir = Path(reports_dir).resolve() / repo_name
    if not repo_dir.is_dir():
        logger.warning("Reports directory does not exist: %s", repo_dir)
        return 0

    if bucket_name:
        # Use provided bucket name as-is (but ensure it follows MinIO rules if possible, though trusting caller here)
        pass
    else:
        bucket_name = _normalize_bucket_name(repo_name)
    
    client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)

    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)
        logger.info("Created MinIO bucket: %s", bucket_name)
    else:
        logger.info("Using existing MinIO bucket: %s", bucket_name)

    uploaded = 0
    for f in repo_dir.rglob("*"):
        if not f.is_file():
            continue
        rel = f.relative_to(repo_dir)
        object_name = rel.as_posix()
        try:
            client.fput_object(bucket_name, object_name, str(f))
            uploaded += 1
            logger.debug("Uploaded %s -> %s/%s", f.name, bucket_name, object_name)
        except Exception as e:
            logger.error("Failed to upload %s: %s", f, e)
    logger.info("Uploaded %d objects to MinIO bucket %s", uploaded, bucket_name)
    return uploaded


def main():
    import argparse

    ap = argparse.ArgumentParser(description="Upload report files to MinIO bucket")
    ap.add_argument("--reports-dir", type=Path, default=Path("reports"), help="Base reports directory")
    ap.add_argument("--repo", required=True, help="Repository name (subfolder under reports-dir)")
    ap.add_argument("--endpoint", default=None, help="MinIO endpoint (default: MINIO_ENDPOINT)")
    ap.add_argument("--access-key", default=None, help="MinIO access key (default: MINIO_ACCESS_KEY)")
    ap.add_argument("--secret-key", default=None, help="MinIO secret key (default: MINIO_SECRET_KEY)")
    ap.add_argument("--bucket", default=None, help="Explicit bucket name (overrides repo-based name)")
    ap.add_argument("--insecure", action="store_true", help="Use HTTP for MinIO")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    n = upload_reports_to_minio(
        args.reports_dir,
        args.repo,
        endpoint=args.endpoint,
        access_key=args.access_key,
        secret_key=args.secret_key,
        secure=not args.insecure,
        bucket_name=args.bucket,
    )
    print(f"Uploaded {n} files to MinIO")


if __name__ == "__main__":
    main()
