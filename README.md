# simtrace2-pysniff

Python-based replacement for `simtrace2-sniff` — SIM card communication sniffer
for Osmocom SIMtrace2 hardware (firmware in trace mode).

**Single dependency**: PyUSB (libusb wrapper). No libosmocore, no libosmosim.

## Quick Start

```sh
# Install + run
pip install pyusb
python -m simtrace2_pysniff
```

Or use the bundled startup script:

```sh
./sniff-start.sh                                 # hex dump to stdout
./sniff-start.sh --gsmtap 127.0.0.1:4729         # + Wireshark GSMTAP
./sniff-start.sh --pcap trace.pcap               # save PCAP for later
./sniff-start.sh --inactivity-timeout 30         # reconnect on silence
```

The startup script performs a pre-flight USB permission check and prints
install instructions if the udev rule is missing (see below).

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

  --gsmtap HOST[:PORT]      Send ATR/TPDU as GSMTAP over UDP (default port 4729)
  --pcap FILE               Write sniffed data to PCAP file for Wireshark
  --output, -o FILE         Write hex dump to file
  --no-stdout               Suppress hex dump to stdout
  --vendor HEX              USB vendor ID (default: 0x1d50)
  --product HEX             USB product ID (default: auto-detect)

Recovery options:
  --no-reconnect            Exit on USB disconnect instead of reconnecting
  --inactivity-timeout SEC  Reconnect after N seconds of silence (default: disabled)
```

## Library Usage

```python
from simtrace2_pysniff import SniffSession

session = SniffSession(inactivity_timeout=30.0)
for msg in session.iter_messages():
    print(f"{msg.type}: {msg.data.hex()}")
```

## Output

- **stdout**: `ATR: 3b 9e ...`, `TPDU: a0 a4 00 00 02 3f 00`, `Card state change: reset de-asserted`
- **GSMTAP**: ATR (subtype 1) and TPDU (subtype 2) over UDP to Wireshark
- **PCAP**: all messages as GSMTAP-encapsulated packets (LINKTYPE 155), openable in Wireshark

## Recovery

The tool survives hardware resets, cable disconnects, and firmware hangs
by default — it reconnects with exponential backoff (1s → 30s cap).
Use `--inactivity-timeout` to also trigger reconnect on silent firmware hangs.
