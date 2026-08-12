#!/bin/bash
# simtrace2-pysniff-server startup script
#
# Usage: ./server-start.sh [--capture gsmtap|direct] [--port PORT] [--db PATH] [--gsmtap-port PORT]
#
# Options set via environment variables act as defaults; CLI flags override them.

set -euo pipefail
shopt -s nullglob

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

CAPTURE="${CAPTURE:-gsmtap}"
PORT="${PORT:-8081}"
DB="${DB:-}"
GSMTAP_PORT="${GSMTAP_PORT:-4729}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --capture)       CAPTURE="$2"; shift 2 ;;
        --port)          PORT="$2"; shift 2 ;;
        --db)            DB="$2"; shift 2 ;;
        --gsmtap-port)   GSMTAP_PORT="$2"; shift 2 ;;
        *)               EXTRA_ARGS+=("$1"); shift ;;
    esac
done

if [[ "$CAPTURE" == "direct" ]]; then
    bad_perms=0

    for devdir in /sys/bus/usb/devices/*/; do
        [[ -f "${devdir}busnum" ]] || continue
        [[ -f "${devdir}devnum" ]] || continue
        [[ -f "${devdir}uevent" ]] || continue

        vid=$(grep -oP 'PRODUCT=\K[a-f0-9]+' "${devdir}uevent" 2>/dev/null || true)
        [[ "$vid" == "1d50" ]] || continue

        busnum=$(<"${devdir}busnum")
        devnum=$(<"${devdir}devnum")
        node=$(printf '/dev/bus/usb/%03d/%03d' "$busnum" "$devnum")

        if [[ ! -e "$node" ]]; then
            continue
        fi

        if [[ -w "$node" ]]; then
            break
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
        exit 3
    fi
fi

ARGS=()
ARGS+=(--capture "$CAPTURE")
ARGS+=(--port "$PORT")
[[ -n "$DB" ]] && ARGS+=(--db "$DB")
[[ "$CAPTURE" == "gsmtap" ]] && ARGS+=(--gsmtap-port "$GSMTAP_PORT")
ARGS+=("${EXTRA_ARGS[@]}")

echo "Starting simtrace2-pysniff-server..." >&2
exec env PYTHONPATH="$PROJECT_DIR" python3 -m simtrace2_pysniff.server "${ARGS[@]}"
