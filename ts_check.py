#!/usr/bin/env python3
"""
ts_check.py - Flag Windows files (copied via robocopy) with suspicious timestamps.

Flags:
  MOD_BEFORE_CREATE  - modified time earlier than creation time
  CREATED_RECENT     - created within the last N days (default 42 = 6 weeks)
  MODIFIED_RECENT    - modified within the last N days

Creation time sources (tried in order):
  1. ntfs-3g xattr  system.ntfs_crtime  (Windows FILETIME, little-endian)
  2. `stat -c %W`   (statx birth time; works on some drivers, returns 0/- if not)

Usage:
  sudo mount -o ro /dev/sdX1 /mnt/evidence
  python3 ts_check.py /mnt/evidence -o results.csv
  python3 ts_check.py /mnt/evidence --days 42 --all   # include unflagged files


  Before the full run, check that creation times are readable on one file with getfattr -n system.ntfs_crtime -e hex /mnt/evidence/somefile. 
  If that fails and stat -c %W shows 0, the drive's filesystem or driver isn't exposing birth time, and only the modified-time check will work. In that case the script prints a warning.

"""

import argparse
import csv
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

FILETIME_EPOCH_DIFF = 116444736000000000  # 100ns intervals between 1601 and 1970


def get_crtime(path):
    """Return (creation_datetime_utc or None, source_string)."""
    # 1. ntfs-3g extended attribute
    try:
        raw = os.getxattr(path, "system.ntfs_crtime", follow_symlinks=False)
        ft = int.from_bytes(raw[:8], "little")
        ts = (ft - FILETIME_EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc), "ntfs_xattr"
    except (OSError, ValueError):
        pass
    # 2. statx birth time via coreutils stat
    try:
        out = subprocess.run(
            ["stat", "-c", "%W", "--", path],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if out and out not in ("0", "-"):
            return datetime.fromtimestamp(int(out), tz=timezone.utc), "statx"
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None, "unavailable"


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="Directory to scan")
    ap.add_argument("-o", "--output", default="ts_check_results.csv")
    ap.add_argument("--days", type=int, default=42, help="Recent window in days (default 42)")
    ap.add_argument("--all", action="store_true", help="Write every file, not just flagged ones")
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        sys.exit(f"Not a directory: {args.root}")

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    counts = {"scanned": 0, "flagged": 0, "no_crtime": 0, "errors": 0}

    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "created_utc", "modified_utc", "crtime_source",
                    "flags", "size_bytes"])

        for dirpath, _dirs, files in os.walk(args.root, onerror=lambda e: None):
            for name in files:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    counts["errors"] += 1
                    continue
                counts["scanned"] += 1

                mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                ctime, src = get_crtime(path)
                if ctime is None:
                    counts["no_crtime"] += 1

                flags = []
                # 1-second tolerance to avoid rounding noise
                if ctime and mtime < ctime - timedelta(seconds=1):
                    flags.append("MOD_BEFORE_CREATE")
                if ctime and ctime >= cutoff:
                    flags.append("CREATED_RECENT")
                if mtime >= cutoff:
                    flags.append("MODIFIED_RECENT")

                if flags:
                    counts["flagged"] += 1
                if flags or args.all:
                    w.writerow([path, fmt(ctime), fmt(mtime), src,
                                ";".join(flags), st.st_size])

    print(f"Scanned: {counts['scanned']}  Flagged: {counts['flagged']}  "
          f"No creation time: {counts['no_crtime']}  Errors: {counts['errors']}")
    print(f"Results: {args.output}")
    if counts["scanned"] and counts["no_crtime"] == counts["scanned"]:
        print("WARNING: no creation times found. Check the mount driver "
              "(ntfs-3g exposes system.ntfs_crtime; FAT/some drivers do not).",
              file=sys.stderr)


if __name__ == "__main__":
    main()
