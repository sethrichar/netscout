# Changelog

All notable changes to netscout. Working revisions are `0.x`; published
releases are whole numbers. Versions are never removed — only revised up.

## v0.8 — Hardening pass (adversarial review: 56 confirmed findings fixed)

Every subsystem was reviewed by independent finders and each finding verified
by three skeptics before being fixed. Highlights:

**False alarms removed**
- The OS ARP cache is no longer consulted in active capture mode (its
  minutes-old entries seeded phantom "online" devices, bogus "went offline"
  events and false IP conflicts at every start). Cache entries are hearsay
  for conflict detection in passive mode too.
- LLDP/CDP management addresses are attributes only — the per-port MAC that
  sends LLDP is not the MAC that answers ARP for the switch IP, which raised
  a recurring false conflict on the gateway.
- mDNS answers that carry A records for other hosts (Bonjour reflectors,
  sleep proxies) are not attributed to the sender; SRV targets name the host
  only when the same packet proves it.
- DHCP OFFER no longer binds an address (only ACK does); relay agents are
  labelled as relays, not servers.
- IPAM: an offline device's last address is shown as "last known", not as a
  live claim; two MACs on one address count as a conflict only when seen
  within the conflict window of each other (a DHCP lease change is not a
  conflict).
- Hostnames no longer flap between DHCP and mDNS names of equal priority;
  services from mDNS are merged as a union instead of replaced per packet.

**Crashes and lifecycle**
- Switching interfaces during an ARP sweep (or a dead capture) dereferenced a
  freed pcap handle. Sessions now carry a closed flag; sweeps are cancelled
  and awaited before capture is torn down; the target interface is validated
  before the current one is closed.
- A capture that dies on its own (cable pulled) is reported as an event and
  the tool drops to passive mode instead of silently showing "capturing".
- Ctrl-C no longer stalls two seconds waiting for SSE streams.
- Cleared conflicts and the "this machine" marker are persisted (attr
  deletions reached memory only).

**Security**
- Local API rejects cross-site browser requests (Sec-Fetch-Site / Origin
  checks) and requires `application/json`, closing a CSRF hole; loopback
  Host check now covers IPv6 forms.
- CSV exports neutralise spreadsheet formula injection from network-sourced
  strings.

**Robustness**
- Subnets are validated (IPv4, at most /16, gateway inside); reservations
  must lie inside their subnet; one bad subnet no longer breaks the listing.
- Import: unparseable cells skip the row with a warning instead of aborting;
  unrecognised IP/MAC headers are guessed from the data; "label" beats
  "hostname"; duplicate addresses are reported; netscout's own devices CSV
  re-imports as labels only; dry-run counts match the real run.
- Default interface skips VPN tunnels and virtual adapters; a remembered
  interface is only reused when it is up with an address; default sweeps are
  narrowed to a /24 on wide or link-local subnets.
- Linux "any" (SLL2) frames, QinQ inner VLAN, IPv6 LLDP chassis IDs, binary
  IDs rendered as hex, localized Windows `arp -a` output.
- SQLite path escaping for `#`/`?`/`%`, fixed-width timestamps so SQL ordering
  is chronological, observation rows pruned after 7 days.
- Running under `sudo` on macOS hands the data directory back to the user;
  ANSI colours are disabled when output is not a terminal; Windows console VT
  mode is enabled for every command.

**UI**
- Background refreshes no longer discard a reservation form or unsaved drawer
  edits; "last seen" sorts numerically; event list is trimmed; errors from
  delete/clear actions are shown; scan CIDR can be cleared.

**Docs & packaging**
- `LICENSE` (MIT) and `THIRD_PARTY_NOTICES.md` added; README licence text
  corrected; macOS Gatekeeper instructions updated for macOS 15 (xattr or
  "Open Anyway"); Npcap wording fixed; release archives ship docs/, LICENSE
  and notices so README links resolve.

## v0.7 — Phase 6 (prep): packaging + release

- Release workflow on tag push: macOS universal binary (arm64 + amd64 via
  `lipo`, built on macOS), Windows amd64 `.exe` (cross-compiled, no cgo),
  Linux amd64; each zipped with README, CHANGELOG and a platform INSTALL
  guide; GitHub release created with notes extracted from this changelog.
  `v0.x` tags publish as pre-releases, whole-number tags as releases.
- `netscout doctor` — first-run checklist: data dir, vendor DB, usable
  interfaces, and a real capture-open test with the platform-specific fix
  printed on failure.
- `docs/INSTALL-macOS.md` (quarantine flag, sudo vs ChmodBPF) and
  `docs/INSTALL-Windows.md` (Npcap, SmartScreen). Npcap is deliberately not
  bundled.
- README rewritten as user documentation; CLAUDE.md updated.
- Fixed the Windows console VT helper (wrong handle type broke the Windows
  build since v0.2); CI now vets the Windows cross-compile on Linux too.

Still to do before tagging `v1`: run the release build on a real macOS and
Windows machine and confirm a fresh install sees devices within two minutes.

## v0.6 — Phase 5: local web UI

- `netscout ui` (also the default when the binary is run with no arguments,
  e.g. double-clicked): captures and serves a single-page UI on
  `127.0.0.1:<random port>`, opening the browser automatically (`--no-open`,
  `--port`, `--scan`, `--scan-every 5m`). Loopback only, with a Host-header
  check against DNS rebinding.
- **Live** tab: sortable, filterable device table (online state, IP, MAC,
  vendor, name, tags, services/info, last seen) updating via server-sent
  events; click a row for a drawer with every fact, IP history, observations,
  events and inline label/tags/notes editing, "reserve this IP", forget.
- **Subnets** tab: add/edit/delete subnets, a colour heatmap of every address
  (free / reserved / in use / match / mismatch / conflict, online dot, gateway
  marker), click any cell to see who is there and reserve it, status-filtered
  address table, per-subnet scan.
- **Events** tab: live log with kind filters; conflicts flagged in the tab
  badge and as toasts, clearable in place.
- **Settings** tab: switch capture interface without restarting, scan now /
  repeat every N minutes, vendor DB status + one-click update from Wireshark,
  MAC lookup box, export (JSON / devices CSV / plan CSV), import a plan with
  dry run.
- JSON API under `/api/*` for everything above; `/api/stream` is SSE.
- Runtime refactor: capture can be stopped and reopened on another interface
  while the engine keeps its state; periodic scan scheduler; OUI hot-swap.
- Vanilla HTML/CSS/JS embedded in the binary — no build step, works offline.

## v0.5 — Phase 4: IPAM core

- Subnets (CIDR, name, VLAN, gateway, notes) and reservations (IP → MAC +
  label) with CRUD in the store; most-specific-subnet lookup for any IP.
- `ipam` package (pure, fully unit-tested): per-address status — free,
  reserved, in-use, match, mismatch (squatter on a reserved IP, or the reserved
  MAC sitting elsewhere), conflict — plus summary counts, history of previous
  occupants, next-free search, and a "current binding" rule (seen within a
  window, or a device's most recent address).
- CLI: `subnet add|set|list|show|rm|free`, `reserve` / `unreserve` /
  `reservations`, `devices [filter]`, `device show|set|rm` (labels, notes,
  tags; accepts MAC, IP, label or hostname), `events`.
- `export --csv|--json` (devices, or `--what reservations` for the IP plan;
  JSON is a full re-importable snapshot) and `import <file>` for client IP
  sheets: loose CSV header matching (ip/address, mac, name/label/device,
  notes, subnet, tags, vlan), headerless and tab/semicolon files, `--subnet`,
  `--auto-subnets`, `--dry-run`. Plan labels are carried onto devices that
  have none.
- Devices created only from a plan show "never" seen until observed; devices
  recorded before the vendor DB was available are classified on first sighting.

## v0.4 — Phase 3: more parsers + active scan

- `scan` package: rate-limited ARP sweep injected through the capture handle
  (replies flow through the normal parse pipeline), optional ICMP echo sweep
  via an unprivileged datagram socket where the OS allows it, subnet host
  enumeration with a /16 safety cap. A /24 completes in ~5 s with two passes.
- `netscout scan [cidr]` — self-contained sweep that prints IP / MAC / vendor /
  label for everything that answers and records it in the database.
- `netscout sniff --scan [--scan-cidr]` — sweep first, then keep listening.
- DHCP (hostname, vendor class, requested IP, server), mDNS/Bonjour (hostname,
  DNS-SD services incl. Dante `_netaudio-*`), LLDP (chassis, port, sysname,
  sysdesc, management IP, capabilities) and CDP parsers are now exercised
  end-to-end; the live table shows the richest facts in its INFO column with
  friendly service names (Dante, AirPlay, Q-SYS, …).
- IP conflict detection (same IP claimed by two MACs within the conflict
  window) raises a `conflict` event, marks both devices and highlights them in
  red in the terminal. Lease changes after the previous owner has gone quiet
  are not flagged.

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
