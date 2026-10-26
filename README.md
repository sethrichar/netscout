# netscout

**LAN sniffer + IPAM with offline MAC vendor lookup — built for show-site / AV /
Dante networks.** One binary for macOS and Windows. Plug into the switch, run it,
and within seconds know who's on the network, what IPs are taken, what the plan
said should be there, and whether anything is conflicting.

## What it does

- **Discover** — passive capture of ARP, DHCP, mDNS/Bonjour (Dante, AirPlay,
  printers…), LLDP/CDP and plain IPv4, plus on-demand ARP sweeps that wake up
  gear that ignores ping.
- **Identify** — every MAC resolved against the bundled Wireshark vendor
  database (58k+ prefixes, 24/28/36-bit), fully offline. Randomised phone MACs
  are flagged, not mislabelled.
- **Track** — live device table with IP history, hostnames, services, labels,
  tags and notes. Devices go offline after a quiet window and come back.
- **Catch conflicts** — the same IP claimed by two MACs is flagged loudly, in
  the terminal and the UI.
- **Plan vs. reality (IPAM)** — register subnets, import the client's IP sheet,
  and see every address as free / reserved / in use / **match** / **mismatch**
  (squatter, or the device is on the wrong IP) / **conflict**.
- **Document** — export devices or the plan as CSV, or everything as JSON for
  the show file.

## Quick start

```sh
netscout doctor          # checks permissions, interface, vendor DB
netscout                 # opens the live web UI in your browser
```

That's it. `netscout` with no arguments (or a double-click) starts capturing on
your default interface and opens `http://127.0.0.1:<port>`.

Prefer the terminal?

```sh
sudo netscout sniff -i en0 --scan        # live table, sweep the subnet first
netscout scan 10.0.0.0/24                # one-off ARP sweep, prints what answered
netscout lookup 00:1d:c1:12:34:56        # → Audinate Pty L (Dante)
```

### Requirements

| | |
|---|---|
| **macOS** | Capture needs `/dev/bpf*` access: run with `sudo`, or install Wireshark with its **ChmodBPF** component once. Unsigned builds need the quarantine flag removed (`xattr -d com.apple.quarantine netscout`) or right-click → Open. See [docs/INSTALL-macOS.md](docs/INSTALL-macOS.md). |
| **Windows** | Install [Npcap](https://npcap.com/#download) (WinPcap API-compatible mode). Not bundled. See [docs/INSTALL-Windows.md](docs/INSTALL-Windows.md). |
| **Linux** | Works too (`sudo` or `setcap cap_net_raw,cap_net_admin=eip netscout`), but isn't a release target. |

Without capture permission netscout still runs in **passive mode** (OS ARP table
only) and prints the exact fix.

## The web UI

| Tab | What you get |
|---|---|
| **Live** | Sortable, filterable device table updating in real time. Click a row: every fact learned, IP history, observations, inline label / tags / notes, "reserve this IP", forget. |
| **Subnets** | Heatmap of every address in a subnet coloured by status, with online dots and the gateway marked. Click a cell to see who's there and reserve it. Status-filtered table underneath. |
| **Events** | Conflicts, new devices, IP changes, hostname changes, offline/online, scans. Conflicts can be cleared once fixed. |
| **Settings** | Switch interface, scan now / every N minutes, update the vendor DB from Wireshark, quick MAC lookup, export (JSON / CSV), import an IP plan with dry run. |

Everything is served from `127.0.0.1` only. No accounts, no cloud, no telemetry.

## CLI reference

```
netscout                      web UI (default)        netscout ui [--port N] [--no-open] [--scan] [--scan-every 5m]
netscout sniff [-i IFACE]     live terminal table     --scan, --no-tui, --filter <bpf>, --online-window 5m
netscout scan [CIDR]          ARP (+--icmp) sweep     --passes 2 --rate 250 --settle 2s
netscout ifaces               list interfaces (default marked *)
netscout doctor               first-run checklist

netscout lookup <mac…>        vendor lookup           --search <vendor>, --json
netscout update-oui           refresh the vendor DB from wireshark.org

netscout devices [filter]     list known devices      --online, --json
netscout device show|set|rm   details / label, notes, tags / forget
netscout events               recorded events         --kind conflict -n 50

netscout subnet add|set|list|show|rm|free
netscout reserve <ip> [mac] --label "Dante — CL5 primary"
netscout unreserve <ip>
netscout reservations [subnet]
netscout export --csv|--json [--what devices|reservations] [-o file]
netscout import <file> [--subnet CIDR] [--auto-subnets] [--dry-run]
```

All commands take `--data-dir` to use a different database (handy for one DB
per show).

### A typical show day

```sh
netscout subnet add 10.0.0.0/24 --name "Dante primary" --vlan 10 --gateway 10.0.0.1
netscout import client-ip-sheet.csv          # the plan: name, ip, mac, notes in any column order
netscout                                     # UI: hit "Scan subnet", watch the heatmap fill in
netscout subnet show "Dante primary"         # or in the terminal: what matches, what's missing, what's squatting
netscout export --csv --what reservations -o as-built.csv
```

## Data

| | |
|---|---|
| macOS | `~/Library/Application Support/netscout/netscout.db` |
| Windows | `%APPDATA%\netscout\netscout.db` |
| Linux | `~/.config/netscout/netscout.db` |

A single SQLite file — copy it to back up a show. An updated vendor DB
(`manuf`) lives next to it when you run `update-oui`.

## Build from source

```sh
go build -o netscout ./cmd/netscout
go test ./...
```

Go 1.26+. Linux needs `libpcap-dev`; macOS and Windows need nothing extra at
build time (Windows loads `wpcap.dll` at runtime, no cgo). macOS binaries must
be built on macOS. `go run ./tools/manufconv` regenerates the bundled vendor
file from Wireshark's `manuf-data.c`.

## Versioning

Working revisions are `v0.x` (pre-releases); published releases are whole
numbers (`v1`, `v2`). Versions are never deleted — only revised up. Every bump
has an entry in [CHANGELOG.md](CHANGELOG.md). Pushing a tag builds and
publishes binaries (macOS universal, Windows amd64, Linux amd64) via GitHub
Actions.

## Roadmap

See [PLAN.md](PLAN.md). v2 ideas: SNMP switch polling (MAC → port), Dante
device-name decoding, show-doc export templates, scheduled diff reports.

## License

MIT for netscout. The bundled vendor data is from the
[Wireshark](https://www.wireshark.org/) project (GPL-2.0-or-later data file,
redistributed unmodified in text form).
