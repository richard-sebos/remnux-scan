#!/usr/bin/env bash
#===============================================================================
# remnux-triage.sh
# Batch static triage of suspicious files on a REMnux workstation.
#
# Classifies files by type (Office/RTF, PDF, image, other), runs the
# appropriate offline static-analysis tools per type, logs per-file output,
# and produces a summary of flagged items.
#
# Usage:
#   ./remnux-triage.sh                        # scans the SCAN_DIRS array below
#   ./remnux-triage.sh -o /path/to/output_dir # same, custom output dir
#   ./remnux-triage.sh dir1 dir2 ...          # override array from command line
#
# Notes:
#   - Read-only against the sample directory; never executes samples.
#   - Skips any tool not installed; notes it in the log instead of failing.
#   - Optional YARA sweep runs if YARA_RULES is set to a rules file/dir.
#===============================================================================
set -u

#-------------------------------------------------------------------------------
# Directories to scan — edit this list for your environment.
# Any directories passed on the command line override this array.
#-------------------------------------------------------------------------------
SCAN_DIRS=(
    "/cases/samples/email-attachments"
    "/cases/samples/downloads"
    "/cases/samples/usb-recovered"
    "/cases/samples/fileshare-suspect"
    "/cases/samples/quarantine-export"
)

OUT_DIR="./triage-$(date +%Y%m%d-%H%M%S)"
YARA_RULES="${YARA_RULES:-}"          # export YARA_RULES=/opt/rules/index.yar to enable
FLAG_LOG=""                            # set in main after OUT_DIR exists

# Parse args: -o <dir> sets output; any remaining args replace SCAN_DIRS
CLI_DIRS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) OUT_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-o output_dir] [dir1 dir2 ...]" >&2
            exit 0 ;;
        *)  CLI_DIRS+=("$1"); shift ;;
    esac
done
[[ ${#CLI_DIRS[@]} -gt 0 ]] && SCAN_DIRS=("${CLI_DIRS[@]}")

# Validate: warn on missing dirs, bail only if none are usable
VALID_DIRS=()
for d in "${SCAN_DIRS[@]}"; do
    if [[ -d "$d" ]]; then
        VALID_DIRS+=("$d")
    else
        echo "WARNING: skipping missing directory: $d" >&2
    fi
done
if [[ ${#VALID_DIRS[@]} -eq 0 ]]; then
    echo "ERROR: none of the scan directories exist." >&2
    exit 1
fi
SCAN_DIRS=("${VALID_DIRS[@]}")

mkdir -p "$OUT_DIR"/{office,pdf,image,other,logs}
FLAG_LOG="$OUT_DIR/FLAGGED.txt"
SUMMARY="$OUT_DIR/summary.txt"
: > "$FLAG_LOG"
: > "$SUMMARY"

#-------------------------------------------------------------------------------
# Helpers
#-------------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

log_run() {
    # log_run <logfile> <label> <command...>
    local logfile="$1" label="$2"; shift 2
    if have "$1"; then
        {
            echo "=== $label : $* ==="
            "$@" 2>&1
            echo
        } >> "$logfile"
    else
        echo "=== $label : SKIPPED ($1 not installed) ===" >> "$logfile"
    fi
}

flag() {
    # flag <file> <reason>
    echo "[FLAG] $1 :: $2" | tee -a "$FLAG_LOG"
}

classify() {
    # Echo one of: office, pdf, image, other
    local f="$1"
    local mime ext
    mime=$(file -b --mime-type "$f")
    ext="${f##*.}"; ext="${ext,,}"

    case "$mime" in
        application/pdf) echo pdf; return ;;
        image/*)         echo image; return ;;
        application/msword|\
        application/vnd.openxmlformats-officedocument.*|\
        application/vnd.ms-excel*|\
        application/vnd.ms-powerpoint*|\
        text/rtf|application/rtf)
                         echo office; return ;;
    esac

    # Fall back to extension — mime detection misses some malformed samples,
    # and malformed is exactly what we're looking for.
    case "$ext" in
        doc|docx|docm|dot|dotm|xls|xlsx|xlsm|xlsb|ppt|pptx|pptm|rtf)
                         echo office ;;
        pdf)             echo pdf ;;
        png|jpg|jpeg|gif|bmp|tif|tiff|webp|ico)
                         echo image ;;
        *)               echo other ;;
    esac
}

#-------------------------------------------------------------------------------
# Per-type analysis
#-------------------------------------------------------------------------------
scan_office() {
    local f="$1" logfile="$2"
    log_run "$logfile" "oleid"    oleid "$f"
    log_run "$logfile" "mraptor"  mraptor "$f"
    log_run "$logfile" "olevba"   olevba --deobf "$f"

    # RTF gets its own object extractor
    if [[ "${f,,}" == *.rtf ]] || file -b "$f" | grep -qi 'rich text'; then
        log_run "$logfile" "rtfobj" rtfobj "$f"
    fi

    # Flagging heuristics
    grep -qiE 'SUSPICIOUS|AutoExec|Base64|Hex String|Dridex' "$logfile" && \
        flag "$f" "olevba/mraptor suspicious indicators"
    grep -qi 'VBA Macros.*True' "$logfile" && \
        flag "$f" "contains VBA macros"
}

scan_pdf() {
    local f="$1" logfile="$2"
    log_run "$logfile" "pdfid"      pdfid "$f"
    log_run "$logfile" "pdf-parser" pdf-parser -a "$f"

    # Flag on risky PDF features with nonzero counts
    grep -E '/(JS|JavaScript|OpenAction|AA|Launch|EmbeddedFile|RichMedia|XFA)\b' "$logfile" \
        | grep -vE ' 0($| )' | grep -q . && \
        flag "$f" "risky PDF features (JS/OpenAction/Launch/EmbeddedFile)"
}

scan_image() {
    local f="$1" logfile="$2"
    log_run "$logfile" "exiftool" exiftool "$f"
    log_run "$logfile" "binwalk"  binwalk "$f"
    # zsteg is PNG/BMP only
    case "$(file -b --mime-type "$f")" in
        image/png|image/bmp) log_run "$logfile" "zsteg" zsteg "$f" ;;
    esac

    grep -qiE 'Zip archive|executable|PE32|ELF|RAR|7-zip' "$logfile" && \
        flag "$f" "embedded archive/executable inside image"
}

scan_other() {
    local f="$1" logfile="$2"
    log_run "$logfile" "file"    file "$f"
    log_run "$logfile" "strings-preview" bash -c "strings -n 8 '$f' | head -100"
    have floss && log_run "$logfile" "floss" floss -q "$f"

    grep -qiE 'powershell|cmd\.exe|wscript|http://|https://|\-enc ' "$logfile" && \
        flag "$f" "suspicious strings (PowerShell/URL/encoded command)"
}

#-------------------------------------------------------------------------------
# Main loop
#-------------------------------------------------------------------------------
declare -A COUNTS=( [office]=0 [pdf]=0 [image]=0 [other]=0 )
TOTAL=0

echo "Triage started $(date)"                       | tee -a "$SUMMARY"
echo "Scan directories (${#SCAN_DIRS[@]}):"          | tee -a "$SUMMARY"
printf '  %s\n' "${SCAN_DIRS[@]}"                    | tee -a "$SUMMARY"
echo "Output: $OUT_DIR"                             | tee -a "$SUMMARY"
echo "---------------------------------------------" | tee -a "$SUMMARY"

while IFS= read -r -d '' f; do
    TOTAL=$((TOTAL+1))
    type=$(classify "$f")
    COUNTS[$type]=$(( COUNTS[$type] + 1 ))

    base=$(basename "$f")
    sha=$(sha256sum "$f" | cut -c1-12)
    logfile="$OUT_DIR/logs/${type}_${base}_${sha}.log"

    {
        echo "FILE:   $f"
        echo "TYPE:   $type"
        echo "SIZE:   $(stat -c%s "$f") bytes"
        echo "SHA256: $(sha256sum "$f" | awk '{print $1}')"
        echo "MIME:   $(file -b --mime-type "$f")"
        echo "============================================="
    } > "$logfile"

    echo "[$type] $base"
    case "$type" in
        office) scan_office "$f" "$logfile" ;;
        pdf)    scan_pdf    "$f" "$logfile" ;;
        image)  scan_image  "$f" "$logfile" ;;
        other)  scan_other  "$f" "$logfile" ;;
    esac

    # Optional YARA sweep across everything
    if [[ -n "$YARA_RULES" ]] && have yara; then
        log_run "$logfile" "yara" yara -r "$YARA_RULES" "$f"
        tail -n 20 "$logfile" | grep -v '^===' | grep -q . && \
            flag "$f" "YARA rule match"
    fi

    # Sort a copy (not the original) into the type bucket for later review
    cp -n "$f" "$OUT_DIR/$type/" 2>/dev/null
done < <(find "${SCAN_DIRS[@]}" -type f -print0)

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------
{
    echo "Files scanned: $TOTAL"
    for t in office pdf image other; do
        printf "  %-8s %d\n" "$t:" "${COUNTS[$t]}"
    done
    echo
    if [[ -s "$FLAG_LOG" ]]; then
        echo "FLAGGED ITEMS ($(wc -l < "$FLAG_LOG")):"
        cat "$FLAG_LOG"
    else
        echo "No files flagged by heuristics. Review logs/ for detail."
    fi
    echo
    echo "Triage finished $(date)"
} | tee -a "$SUMMARY"

echo
echo "Done. Per-file logs in: $OUT_DIR/logs/"
echo "Flag summary:          $FLAG_LOG"
