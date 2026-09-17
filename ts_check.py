#!/usr/bin/env python3
"""
ts_check.py - Flag Windows files (copied via robocopy) with suspicious timestamps.

Flags:
  MOD_BEFORE_CREATE  - modified time earlier than creation time
  CREATED_RECENT     - created within the last N days (default 42 = 6 weeks)
  MODIFIED_RECENT    - modified within the last N days

MOD_BEFORE_CREATE is normal on Windows when a file is copied (new creation
time, original modified time). Each such file gets a risk rating:

  LOW     Looks like a copy/extract: several files in the same folder share a
          creation time (COPY_BATCH), or the file was created at about the same
          time as its parent folder (FOLDER_COPY).
  MEDIUM  Isolated file with no batch/folder pattern. Could be a single-file
          copy, could be manipulation. Review.
  HIGH    Creation time has a zero sub-second fraction. Genuine NTFS creation
          times carry 100ns precision, while many timestomping tools set whole
          seconds. (Requires ntfs-3g xattr source for full precision.)

Notes column (informational):
  CREATE_ZERO_FRACTION  creation time is an exact whole second
  MTIME_DOS_2SEC        modified time is an even whole second (typical of
                        zip/archive extraction or FAT-origin files)
  MTIME_ZERO_FRACTION   modified time is an exact odd whole second

Creation time sources (tried in order):
  1. ntfs-3g xattr  system.ntfs_crtime  (full 100ns precision)
  2. `stat -c %W`   (statx birth time, whole seconds only; zero-fraction
                     checks on creation time are skipped for this source)

Limitation: a careful attacker can set sub-second values. The definitive
timestomp test is comparing $STANDARD_INFORMATION with $FILE_NAME in the MFT,
which needs the original volume or an image (Sleuth Kit / MFTECmd), not a
robocopy copy.

Usage:
  sudo mount -o ro /dev/sdX1 /mnt/evidence
  python3 ts_check.py /mnt/evidence -o results.csv
  python3 ts_check.py /mnt/evidence --hide-low
  python3 ts_check.py /mnt/evidence --batch-window 30 --min-batch 5
"""
import argparse
import bisect
import csv
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

FILETIME_EPOCH_DIFF = 116444736000000000  # 100ns intervals, 1601 -> 1970
NS = 1_000_000_000
DAY_NS = 86400 * NS
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "": 3}


def get_crtime_ns(path):
    """Return (creation time in ns since epoch or None, source)."""
    try:
        raw = os.getxattr(path, "system.ntfs_crtime", follow_symlinks=False)
        ft = int.from_bytes(raw[:8], "little")
        return (ft - FILETIME_EPOCH_DIFF) * 100, "ntfs_xattr"
    except (OSError, ValueError):
        pass
    try:
        out = subprocess.run(["stat", "-c", "%W", "--", path],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        if out and out not in ("0", "-"):
            return int(out) * NS, "statx_sec"
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None, "unavailable"


def fmt(ns):
    if ns is None:
        return ""
    dt = datetime.fromtimestamp(ns // NS, tz=timezone.utc)
    return f"{dt:%Y-%m-%d %H:%M:%S}.{(ns % NS) // 100:07d}"


def neighbours(sorted_vals, v, window_ns):
    """How many values (including v) fall within +/- window of v."""
    return (bisect.bisect_right(sorted_vals, v + window_ns)
            - bisect.bisect_left(sorted_vals, v - window_ns))


def densest_window(sorted_vals, window_ns):
    """Largest number of values inside any window of the given width."""
    best, best_start, j = 0, None, 0
    for i, v in enumerate(sorted_vals):
        while sorted_vals[j] < v - window_ns:
            j += 1
        if i - j + 1 > best:
            best, best_start = i - j + 1, sorted_vals[j]
    return best, best_start


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="Directory to scan")
    ap.add_argument("-o", "--output", default="ts_check_results.csv")
    ap.add_argument("--days", type=int, default=42,
                    help="Recent window in days (default 42)")
    ap.add_argument("--batch-window", type=int, default=10,
                    help="Seconds either side for creation-time batching (default 10)")
    ap.add_argument("--min-batch", type=int, default=3,
                    help="Files in a folder sharing a creation time to count as a copy batch (default 3)")
    ap.add_argument("--folder-window", type=int, default=60,
                    help="Seconds between folder and file creation to count as a folder copy (default 60)")
    ap.add_argument("--hide-low", action="store_true",
                    help="Omit LOW-risk MOD_BEFORE_CREATE files unless also recent")
    ap.add_argument("--all", action="store_true",
                    help="Write every file, not just flagged ones")
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        sys.exit(f"Not a directory: {args.root}")

    now_ns = int(datetime.now(timezone.utc).timestamp()) * NS
    cutoff_ns = now_ns - args.days * DAY_NS
    batch_ns = args.batch_window * NS
    folder_ns = args.folder_window * NS

    # Pass 1: collect timestamps
    records = []
    dir_cr = {}
    by_dir = defaultdict(list)
    errors = 0
    for dirpath, _dirs, files in os.walk(args.root, onerror=lambda e: None):
        dir_cr[dirpath] = get_crtime_ns(dirpath)[0]
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                errors += 1
                continue
            cr, src = get_crtime_ns(path)
            records.append((path, dirpath, cr, src, st.st_mtime_ns, st.st_size))
            if cr is not None:
                by_dir[dirpath].append(cr)

    for vals in by_dir.values():
        vals.sort()

    # Pass 2: classify
    rows = []
    risk_counts = Counter()
    flagged = no_cr = 0
    for path, dirpath, cr, src, mt, size in records:
        if cr is None:
            no_cr += 1

        notes = []
        if src == "ntfs_xattr" and cr % NS == 0:
            notes.append("CREATE_ZERO_FRACTION")
        if mt % NS == 0:
            notes.append("MTIME_DOS_2SEC" if (mt // NS) % 2 == 0 else "MTIME_ZERO_FRACTION")

        flags, risk, batch, gap_days = [], "", "", ""
        if cr is not None and mt < cr - NS:
            flags.append("MOD_BEFORE_CREATE")
            gap_days = f"{(cr - mt) / DAY_NS:.1f}"
            batch = neighbours(by_dir[dirpath], cr, batch_ns)
            dcr = dir_cr.get(dirpath)
            folder_copy = dcr is not None and abs(cr - dcr) <= folder_ns

            if batch >= args.min_batch:
                notes.append("COPY_BATCH")
            if folder_copy:
                notes.append("FOLDER_COPY")

            if "CREATE_ZERO_FRACTION" in notes:
                risk = "HIGH"
            elif batch >= args.min_batch or folder_copy:
                risk = "LOW"
            else:
                risk = "MEDIUM"
            risk_counts[risk] += 1

        if cr is not None and cr >= cutoff_ns:
            flags.append("CREATED_RECENT")
        if mt >= cutoff_ns:
            flags.append("MODIFIED_RECENT")

        if flags:
            flagged += 1
        if args.hide_low and flags == ["MOD_BEFORE_CREATE"] and risk == "LOW":
            continue
        if flags or args.all:
            rows.append([path, fmt(cr), fmt(mt), src, risk, ";".join(flags),
                         gap_days, batch, ";".join(notes), size])

    rows.sort(key=lambda r: (RISK_ORDER[r[4]], r[0]))
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "created_utc", "modified_utc", "crtime_source", "risk",
                    "flags", "gap_days", "batch_size", "notes", "size_bytes"])
        w.writerows(rows)

    print(f"Scanned: {len(records)}  Flagged: {flagged}  "
          f"No creation time: {no_cr}  Errors: {errors}")
    print(f"Modified-before-created  HIGH: {risk_counts['HIGH']}  "
          f"MEDIUM: {risk_counts['MEDIUM']}  LOW: {risk_counts['LOW']}")
    print(f"Results: {args.output}")

    # Sanity checks
    all_cr = sorted(r[2] for r in records if r[2] is not None)
    if records and not all_cr:
        print("WARNING: no creation times found. Check the mount driver "
              "(ntfs-3g exposes system.ntfs_crtime; FAT/some drivers do not).",
              file=sys.stderr)
    elif len(all_cr) >= 50:
        count, start = densest_window(all_cr, 3600 * NS)
        if count >= 0.5 * len(all_cr):
            print(f"WARNING: {count}/{len(all_cr)} files were created within one hour "
                  f"starting {fmt(start)} UTC. If that matches the robocopy run, "
                  "creation times were probably NOT preserved and the "
                  "MOD_BEFORE_CREATE results are unreliable.", file=sys.stderr)
    if any(r[3] == "statx_sec" for r in records):
        print("NOTE: some creation times came from statx (whole seconds); "
              "HIGH-risk zero-fraction detection is skipped for those files.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
