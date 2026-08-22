# simtrace2-pysniff

Python-based replacement for `simtrace2-sniff` — SIM card communication sniffer
for Osmocom SIMtrace2 hardware (firmware in **trace** mode).  It bundles the
**simtrace-analyser** PWA (in [`frontend/`](frontend/)) and an analysis server
that both captures APDU traffic and serves that PWA.

**Single dependency**: PyUSB (libusb wrapper). No libosmocore, no libosmosim.

## Features

**APDU decoder** (server-side, rendered by the PWA):

- Full APDU decode — CLA per ISO 7816-4 / ETSI coding (logical channel,
  secure messaging, command chaining), INS names from a spec table,
  SFI-aware P1/P2 for READ/UPDATE BINARY and record commands
- Status words — full ISO 7816-4 set plus UICC-specific values:
  `91XX` (proactive command pending), `62F1/F2/F3`, `63F1/F2` (more data),
  `9300` (SAT busy), `9850`, `9862–64`
- SIM Toolkit — SAT (GSM 11.14), CAT (TS 102 223) and USAT (TS 31.111)
  proactive commands with decoded qualifiers, TERMINAL RESPONSE, ENVELOPE
  (Menu Selection, Call Control, SMS-PP download…); tolerates known
  non-compliant legacy-card quirks and preserves unrecognized TLVs
- SMS TPDU — SMS-DELIVER/SUBMIT, SCTS timestamps, UDH information elements
- SCP80 OTA secured packets — SPI bits (ciphering, PoR requirement/mode,
  RC/CC/DS, counter), KIc/KID algorithm + key set, TAR, CNTR/PCNTR;
  Response Packet (PoR) decode on GET RESPONSE
- ATR parse (clock-rate conversion, Fi/Di, T-bitmask) and FCP/FCI TLV

**simtrace-analyser PWA** ([`frontend/`](frontend/)):

- Trace view with Map/List modes — proactive, TERMINAL RESPONSE, ENVELOPE
  and AUTH commands get distinctive styling in map view
- Sessions with deep links (`#session=N`), PCAP import (`.pcap/.pcapng/.cap`),
  search and type filtering
- Installable PWA, dark theme, English/Russian UI

## Prerequisites

- **Python 3.9+**
- **PyUSB** — `pip install pyusb`
- **libusb** — system library, present by default on Linux; on Windows the
  SIMtrace2 driver must be swapped (see [USB Device Access](#usb-device-access))
- **SIMtrace2 hardware** running firmware in *trace* mode
  (VID `1d50`, PID `60e3`, USB class `ff`, subclass `01`). For building and
  flashing trace firmware, see the [upstream SIMtrace2 project](https://gitea.osmocom.org/sim-card/simtrace2).

No other dependencies. PCAP, GSMTAP, and hex dump output use only Python stdlib.

## Install

```sh
git clone https://github.com/anttro/simtrace2-pysniff.git
cd simtrace2-pysniff
pip install pyusb
```

Or install the package into your environment:

```sh
pip install -e .
# then run: simtrace2-pysniff [opts]
```

## Running

Two tools are provided:

### Sniffer CLI (`simtrace2-pysniff`)

Captures SIMtrace2 traffic and writes it to stdout, GSMTAP (Wireshark), or PCAP files.

### Startup script (Linux only)

`./sniff-start.sh` performs a pre-flight USB permission check (prints udev
install instructions if the SIMtrace2 device is not writable) and then
launches the Python module.

```sh
./sniff-start.sh
./sniff-start.sh --format timestamp
./sniff-start.sh --gsmtap 127.0.0.1:4729
./sniff-start.sh --pcap trace.pcap --format atr-time
```

OPTIONS can also be set via environment variables:

```sh
FORMAT=timestamp GSMTAP=127.0.0.1 ./sniff-start.sh
```

### Analysis server + PWA (`simtrace2-pysniff-server`)

Stores captured APDU traffic in SQLite and serves it over HTTP, together with
the bundled **simtrace-analyser** PWA (`frontend/`) on the same origin.  Three
capture modes:

```sh
# Listen for GSMTAP from simtrace2-pysniff (or original simtrace2-sniff):
simtrace2-pysniff-server --capture gsmtap

# Capture directly from SIMtrace2 hardware (no external tool needed):
simtrace2-pysniff-server --capture direct

# Browse/analyse existing captures without a capture backend:
simtrace2-pysniff-server --capture disabled
```

Server options:

```
--host ADDR          HTTP bind address (default: 127.0.0.1)
--port PORT          HTTP server port (default: 8081)
--db FILE            SQLite database path (default: ~/.simtrace-analyser/sessions.db)
--capture MODE       gsmtap | direct | disabled  (default: gsmtap)
--gsmtap-port PORT   UDP port for the GSMTAP listener (default: 4729)
--web-dir PATH       PWA static files directory (default: <repo>/frontend)
```

Then open **http://127.0.0.1:8081/** in a browser — the PWA is served by the
server, so the UI and the API share an origin and no CORS/Private-Network-Access
setup is involved.  Use `--web-dir PATH` to serve a different PWA directory
(default: `<repo>/frontend`).

### Hosted PWA (landing page)

A standalone copy of the PWA is hosted at **https://simtrace.atroshin.ru**.
It is a pure frontend: point it (Settings → Server URL) at a locally running
`simtrace2-pysniff-server`.

> **Browser restriction:** when the PWA is served from a public HTTPS host,
> reaching a local server (`http://127.0.0.1:8081`) requires two things: the
> server must send `Access-Control-Allow-Private-Network: true` (this server
> does), and the browser must be allowed to access the local network — in
> Chrome/Edge/Vivaldi: Site settings → Local network access → allow the site
> (or accept the permission prompt).  Without the browser permission, the
> request to `127.0.0.1` is blocked before any preflight is sent.

### Python module (cross-platform)

```sh
python -m simtrace2_pysniff
python -m simtrace2_pysniff --format timestamp --gsmtap 127.0.0.1:4729
python -m simtrace2_pysniff --pcap trace.pcap
```

If installed via `pip install -e .`, use the console script directly:

```sh
simtrace2-pysniff --format atr-time
```

## USB Device Access

### Linux

A udev rule is required for non-root USB access to the SIMtrace2 device.

```sh
sudo cp 70-simtrace2-pysniff.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Then reconnect the SIMtrace2 USB cable. The rule uses `TAG+="uaccess"`
(systemd-logind ACL) — no group membership or world-writable permissions needed.

### Windows

Windows does not ship a libusb-compatible driver for SIMtrace2. Use
[Zadig](https://zadig.akeo.ie/) to replace the default driver:

1. Download and run **Zadig**
2. Plug in the SIMtrace2 device
3. Select it in the dropdown (VID `1D50`, PID `60E3` — "Osmocom SIMtrace 2")
4. Choose **WinUSB** (or libusbK) as the replacement driver
5. Click **Replace Driver** (one-time operation)

After that, `python -m simtrace2_pysniff` works identically to Linux.

## CLI Options

```
python -m simtrace2_pysniff [OPTIONS]

  --format, -f FORMAT       Output format (default: hex)
                            hex       — plain hex dump
                            timestamp — TPDU lines prefixed with [HH:MM:SS.mmm]
                            atr-time  — TPDU lines prefixed with [SSSS.mmm] from last ATR
  --gsmtap HOST[:PORT]      Send ATR/TPDU as GSMTAP over UDP (default port 4729)
  --pcap FILE               Write sniffed data to PCAP file for Wireshark
  --output, -o FILE         Write hex dump to file
  --no-stdout               Suppress hex dump to stdout
  --vendor HEX              USB vendor ID (default: 0x1d50)
  --product HEX             USB product ID (default: auto-detect)

Recovery options:
  --no-reconnect            Exit on USB disconnect instead of reconnecting
  --reconnect-delay-min SEC Minimum reconnect delay (default: 1.0)
  --reconnect-delay-max SEC Maximum reconnect delay cap (default: 30.0)
  --backoff-factor N        Exponential backoff multiplier (default: 1.5)
  --inactivity-timeout SEC  Reconnect after N seconds of silence (default: disabled)
```

## Output Formats

- **`hex`** (default): plain hex dump — `ATR: 3b 9e ...`, `TPDU: a0 a4 00 00 02 3f 00`
- **`timestamp`**: TPDU lines prefixed with local time — `[14:32:05.123] TPDU: a0 a4 00 00 02 3f 00`
- **`atr-time`**: TPDU lines prefixed with seconds since last ATR — `[0001.234] TPDU: a0 a4 00 00 02 3f 00`

Non-TPDU messages (ATR, PPS, card state changes, Fi/Di) print identically in all formats.

- **GSMTAP**: ATR and APDU messages over UDP (port 4729) to Wireshark
- **PCAP**: ATR/TPDU messages as Ethernet/IP/UDP/GSMTAP packets, openable in Wireshark

## Background / Daemon

SIGHUP is automatically ignored when stdin is not a terminal (i.e. run in
background or via a pipe). Foreground terminal sessions still respond to
SIGHUP normally.

To run persistently in the background with output to files:

```sh
nohup ./sniff-start.sh --output /tmp/sniff.log &> /tmp/sniff-err.log &
# or
FORMAT=timestamp nohup python -m simtrace2_pysniff --output /tmp/sniff.log &> /tmp/sniff-err.log &
```

## Library Usage

```python
from simtrace2_pysniff import SniffSession

session = SniffSession(inactivity_timeout=30.0)
for msg in session.iter_messages():
    print(f"{msg.type}: {msg.data.hex()}")
```

## Recovery

The tool survives hardware resets, cable disconnects, and firmware hangs
by default — it reconnects with exponential backoff (1s → 30s cap).
Use `--inactivity-timeout` to also trigger reconnect on silent firmware hangs.

## Related

- **[simtrace2](https://gitea.osmocom.org/sim-card/simtrace2)** — the upstream
  SIMtrace2 hardware/firmware project that this tool sniffs from.
