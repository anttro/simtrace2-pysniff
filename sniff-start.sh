#!/bin/bash
# simtrace2-pysniff startup script
#
# Usage: ./sniff-start.sh [--format FORMAT] [--gsmtap HOST[:PORT]] [--pcap FILE] [--output FILE] [--inactivity-timeout SECONDS]
#
# Options set via environment variables act as defaults; CLI flags override them.

set -euo pipefail
shopt -s nullglob

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

GSMTAP="${GSMTAP:-}"
PCAP="${PCAP:-}"
OUTPUT="${OUTPUT:-}"
FORMAT="${FORMAT:-}"
INACTIVITY_TIMEOUT="${INACTIVITY_TIMEOUT:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gsmtap)              GSMTAP="$2"; shift 2 ;;
        --pcap)                PCAP="$2"; shift 2 ;;
        --output|-o)           OUTPUT="$2"; shift 2 ;;
        --format|-f)           FORMAT="$2"; shift 2 ;;
        --inactivity-timeout)  INACTIVITY_TIMEOUT="$2"; shift 2 ;;
        --keep-running|--no-reconnect)
                               EXTRA_ARGS+=("$1"); shift ;;
        *)                     EXTRA_ARGS+=("$1"); shift ;;
    esac
done

check_permissions() {
    local bad_perms=0

    for devdir in /sys/bus/usb/devices/*/; do
        [[ -f "${devdir}busnum" ]] || continue
        [[ -f "${devdir}devnum" ]] || continue
        [[ -f "${devdir}uevent" ]] || continue

        local vid
        vid=$(grep -oP 'PRODUCT=\K[a-f0-9]+' "${devdir}uevent" 2>/dev/null || true)
        [[ "$vid" == "1d50" ]] || continue

        local busnum devnum node
        busnum=$(<"${devdir}busnum")
        devnum=$(<"${devdir}devnum")
        node=$(printf '/dev/bus/usb/%03d/%03d' "$busnum" "$devnum")

        if [[ ! -e "$node" ]]; then
            continue
        fi

        if [[ -w "$node" ]]; then
            return 0
        fi

        bad_perms=1
        echo "Permission denied on $node" >&2
    done

    if [[ $bad_perms -eq 1 ]]; then
        echo "" >&2
        echo "Install the udev rule (then reconnect the device):" >&2
        echo "──────────────────────────────────────────────────" >&2
        echo "  sudo cp '$PROJECT_DIR/70-simtrace2-pysniff.rules' /etc/udev/rules.d/" >&2
        echo "  sudo udevadm control --reload-rules" >&2
        echo "  sudo udevadm trigger" >&2
        echo "──────────────────────────────────────────────────" >&2
        return 1
    fi

    return 0
}

check_permissions || exit 3

ARGS=()
[[ -n "$GSMTAP" ]]             && ARGS+=(--gsmtap "$GSMTAP")
[[ -n "$PCAP" ]]               && ARGS+=(--pcap "$PCAP")
[[ -n "$OUTPUT" ]]             && ARGS+=(--output "$OUTPUT")
[[ -n "$FORMAT" ]]             && ARGS+=(--format "$FORMAT")
[[ "$INACTIVITY_TIMEOUT" != "0" ]] && ARGS+=(--inactivity-timeout "$INACTIVITY_TIMEOUT")
ARGS+=("${EXTRA_ARGS[@]}")

echo "Starting simtrace2-pysniff..." >&2
exec env PYTHONPATH="$PROJECT_DIR" python3 -m simtrace2_pysniff "${ARGS[@]}"
