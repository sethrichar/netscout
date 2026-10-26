# Changelog

All notable changes to netscout. Working revisions are `0.x`; published
releases are whole numbers. Versions are never removed — only revised up.

## v0.3 — Phase 2: MAC vendor lookup

- Bundled Wireshark vendor database (`assets/oui/manuf`, 58k+ assignments:
  IEEE OUI/24, MA-M/28, MA-S/36) embedded in the binary — lookups are fully
  offline. Generated from Wireshark's `epan/manuf-data.c` with
  `tools/manufconv`, since Wireshark ≥ 4.2 no longer ships the text file in git.
- `oui` package: manuf text + C-source parsers, longest-prefix lookup,
  randomized / multicast classification, vendor search, loader that prefers an
  updated copy in the data dir, `Update` that downloads from wireshark.org and
  falls back to the GitHub mirror (validated: never replaces good data with a
  truncated download).
- `netscout lookup <mac…>` (`--json`, `--search <vendor>`),
  `netscout update-oui`.
- Vendor wired into the engine and the live table; randomized MACs show as
  "randomized" rather than "unknown".
- Tests cover Audinate, Yamaha, Shure, QSC, Apple, Cisco, Allen & Heath
  (registered as Audiotonix), 28/36-bit longest-prefix matching and the
  update fallback path.

## v0.2 — Phase 1: passive capture + ARP

- `capture.Session`: pcap live capture with immediate mode, BPF, frame
  injection (for sweeps), drop counters and clean Ctrl-C shutdown.
- `parse` package: ARP (request/reply/probe/gratuitous, VLAN-tagged) plus the
  generic IPv4 liveness observation. DHCP, mDNS/Bonjour (Dante service
  discovery), LLDP and CDP parsers landed early so the dispatcher is complete;
  all are covered by table tests against `testdata/*.pcap` fixtures generated
  by `internal/parse/testdata/gen`.
- `store`: SQLite schema (devices, device_ips, device_attrs, observations,
  events, meta, subnets, reservations) with migrations; observed fields and
  user fields (label/notes/tags) are written independently so edits are never
  clobbered by capture.
- `engine`: merges observations into a live device table, throttles DB
  writes, tracks IP history per MAC, marks devices offline after a quiet
  window, detects IP conflicts (same IP from two MACs inside a window) and
  fans events out to subscribers.
- `netscout sniff -i <iface>`: live terminal table (online state, IP, MAC,
  vendor, host/label, last seen, info) with recent events; `--no-tui` streams
  events as log lines. Falls back to polling the OS ARP table when capture is
  not permitted and prints the exact fix for macOS (sudo / ChmodBPF) or
  Windows (Npcap).
- OS ARP cache reader for Linux, macOS and Windows (also used to seed the
  table at startup).

## v0.1 — Phase 0: scaffold

- Go module `github.com/sethrichar/netscout`, cobra CLI.
- `netscout version` (reads `VERSION`), `netscout ifaces` (pcap + OS interface
  merge, default-route interface marked `*`, Windows friendly descriptions).
- Per-OS data directory resolution (`internal/config`).
- Privilege / Npcap detection with actionable hints.
- GitHub Actions CI: vet + test + build matrix (ubuntu, macOS, Windows) with
  binaries uploaded as artifacts.
- `CLAUDE.md`, `PLAN.md`, `.gitignore`.
