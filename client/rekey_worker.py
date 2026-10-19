"""Admin re-key worker (doc 02 Section 4.4, doc 03 Section 7).

After a revoke bumps an attribute's version, already-encrypted files still sit
under the old versioned policy. This CLI -- not the backend -- decrypts each
affected file with the admin's all-attributes ABE key and re-encrypts it under
the current versions, with a fresh file key, then swaps the S3 object.

The backend deliberately cannot do this: it holds MSK but no attribute key.

Usage:
    python -m client.rekey_worker --job 3
    python -m client.rekey_worker --list
    python -m client.rekey_worker --all --username admin
"""
import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client import vault as vaultlib  # noqa: E402
from client.api import ApiError, DEFAULT_BASE_URL, SecureVaultApi  # noqa: E402


def _bar(prefix, fraction, width=28):
    filled = int(round(fraction * width))
    sys.stdout.write("\r  %s [%s%s] %3d%%" % (prefix, "#" * filled, "." * (width - filled), int(fraction * 100)))
    sys.stdout.flush()


def run_job(vault, job_id, verbose=True):
    """Re-encrypt every pending file in one job. Returns (done, failed)."""
    items = vault.api.rekey_job_files(job_id)
    if not items:
        print("Job %d has no pending files." % job_id)
        return 0, 0

    done = failed = 0
    for index, item in enumerate(items, start=1):
        label = "file %d/%d %s" % (index, len(items), item["file_id"][:8])
        try:
            new_policy = vault.rekey_file(
                job_id, item,
                progress=(lambda f, lbl=label: _bar(lbl, f)) if verbose else None,
            )
            if verbose:
                sys.stdout.write("\n")
            print("  OK   %s -> %s" % (item["file_id"], new_policy))
            done += 1
        except vaultlib.AccessDenied as exc:
            if verbose:
                sys.stdout.write("\n")
            print("  FAIL %s: %s" % (item["file_id"], exc))
            failed += 1
        except (ApiError, OSError, ValueError) as exc:
            if verbose:
                sys.stdout.write("\n")
            print("  FAIL %s: %s" % (item["file_id"], exc))
            failed += 1
    return done, failed


def main(argv=None):
    parser = argparse.ArgumentParser(description="SecureVault admin re-key worker")
    parser.add_argument("--job", type=int, help="re-key job id to process")
    parser.add_argument("--all", action="store_true", help="process every queued/running job")
    parser.add_argument("--list", action="store_true", help="list re-key jobs and exit")
    parser.add_argument("--api", default=DEFAULT_BASE_URL, help="API base URL")
    parser.add_argument("--username", default=os.environ.get("SECUREVAULT_ADMIN", "admin"))
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (local demo only)")
    parser.add_argument("--quiet", action="store_true", help="no progress bars")
    args = parser.parse_args(argv)

    if not (args.job or args.all or args.list):
        parser.error("one of --job, --all, or --list is required")

    password = os.environ.get("SECUREVAULT_ADMIN_PASSWORD") or getpass.getpass(
        "Password for %s: " % args.username
    )

    api = SecureVaultApi(args.api, verify=not args.insecure)
    try:
        vault = vaultlib.login(api, args.username, password)
    except ApiError as exc:
        print("Login failed: %s" % exc.message)
        return 1

    if not vault.user.get("is_admin"):
        print("%s is not an admin; the re-key worker needs the all-attributes admin key." % args.username)
        return 1

    try:
        jobs = vault.api.rekey_jobs()
    except ApiError as exc:
        print("Could not list jobs: %s" % exc.message)
        return 1

    if args.list:
        if not jobs:
            print("No re-key jobs.")
        for j in jobs:
            print(
                "job %-4d attr %-4d v%d -> v%d  %-8s %d/%d files  %s"
                % (j["id"], j["attribute_id"], j["old_version"], j["new_version"],
                   j["status"], j["files_done"], j["files_total"], j["created_at"])
            )
        return 0

    targets = [j["id"] for j in jobs if j["status"] != "done"] if args.all else [args.job]
    if not targets:
        print("Nothing to do.")
        return 0

    total_done = total_failed = 0
    for job_id in targets:
        print("Re-keying job %d..." % job_id)
        done, failed = run_job(vault, job_id, verbose=not args.quiet)
        total_done += done
        total_failed += failed

    print("\nRe-keyed %d file(s), %d failure(s)." % (total_done, total_failed))
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
