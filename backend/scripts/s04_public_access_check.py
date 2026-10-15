"""S-04: the bucket must deny anonymous access (doc 07 Section 1.3, doc 04 Section 3).

This one cannot run under moto -- moto does not evaluate bucket policies or the
public-access block -- so it talks to the REAL bucket named in backend/.env.
It only reads: an unsigned HEAD/GET that is expected to fail.

Usage: python backend/scripts/s04_public_access_check.py
Exit code 0 means the bucket is private.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import boto3  # noqa: E402
import requests  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from backend.app.config import get_settings  # noqa: E402

FAIL = "FAIL"
OK = "OK"


def main() -> int:
    settings = get_settings()
    if settings.storage_backend != "s3":
        print("STORAGE_BACKEND is %r, not 's3'; nothing real to check." % settings.storage_backend)
        return 2

    bucket = settings.s3_bucket
    region = settings.aws_region
    failures = []
    print("Checking bucket %s in %s" % (bucket, region))

    # 1. public access block
    s3 = boto3.client("s3", region_name=region)
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        missing = [k for k, v in config.items() if not v]
        if missing:
            failures.append("public access block incomplete: %s are false" % ", ".join(missing))
            print("  %s public access block: %s are false" % (FAIL, ", ".join(missing)))
        else:
            print("  %s public access block: all four settings enabled" % OK)
    except ClientError as exc:
        failures.append("no public access block configured (%s)" % exc.response["Error"]["Code"])
        print("  %s public access block: not configured" % FAIL)

    # 2. an unsigned, anonymous GET of a known object must be denied
    try:
        listing = s3.list_objects_v2(Bucket=bucket, Prefix=settings.s3_prefix, MaxKeys=1)
    except ClientError as exc:
        print("  could not list the bucket with credentials: %s" % exc)
        return 1

    contents = listing.get("Contents") or []
    if not contents:
        print("  (no objects under %r yet; upload one, then re-run for the anonymous GET check)"
              % settings.s3_prefix)
    else:
        key = contents[0]["Key"]
        url = "https://%s.s3.%s.amazonaws.com/%s" % (bucket, region, key)
        resp = requests.get(url, timeout=30)
        if resp.status_code in (401, 403):
            print("  %s anonymous GET of %s denied with %d" % (OK, key, resp.status_code))
        else:
            failures.append("anonymous GET of %s returned %d" % (key, resp.status_code))
            print("  %s anonymous GET of %s returned %d" % (FAIL, key, resp.status_code))

    # 3. bucket ACL must not be public
    try:
        grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
        public = [
            g for g in grants
            if "AllUsers" in str(g.get("Grantee", {}).get("URI", ""))
            or "AuthenticatedUsers" in str(g.get("Grantee", {}).get("URI", ""))
        ]
        if public:
            failures.append("bucket ACL grants access to %d public group(s)" % len(public))
            print("  %s bucket ACL has public grants" % FAIL)
        else:
            print("  %s bucket ACL has no public grants" % OK)
    except ClientError as exc:
        print("  (could not read the bucket ACL: %s)" % exc.response["Error"]["Code"])

    if failures:
        print("\nS-04 FAILED:")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nS-04 OK: the bucket is private.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
