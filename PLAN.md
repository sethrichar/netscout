# netscout — LAN Sniffer + IPAM with MAC Vendor Lookup

> Working name: `netscout` (rename freely). Cross-platform (macOS + Windows) tool for
> discovering what's on a network, tracking IP/MAC assignments, and identifying devices
> by MAC vendor. Built for show-site / AV / Dante networks where you need to know fast
> who's on the switch, what IPs are taken, and whether anything is conflicting.

This file is the execution plan for Claude Code. Read it fully before starting.
Work phase by phase. Each phase ends with a working, testable binary.

---

## 0. Decisions already made (change only if there's a real blocker)

| Decision | Choice | Why |
|---|---|---|
| Language | **Go 1.22+** | Single static binary, trivial cross-compile, strong packet libs, fast to iterate. |
| Packet capture | `github.com/google/gopacket` + `gopacket/pcap` | De-facto standard. On Windows it loads `wpcap.dll` (Npcap) at runtime — no cgo. On macOS it links libpcap (ships with the OS) via cgo. |
| Storage | SQLite via `modernc.org/sqlite` | Pure Go (no cgo), one file DB, easy to back up/version. |
| MAC vendor DB | Wireshark `manuf` file (IEEE OUI/MA-M/MA-S merged), **bundled** via `go:embed` | Works fully offline. Add an `update-oui` command to refresh it. |
| UI | Phase 1–4: CLI. Phase 5: **local web UI** (Go serves embedded HTML/JS on `127.0.0.1:<port>`, auto-opens browser) | No Electron, no Wails, no frontend toolchain. One binary. |
| Config/data location | macOS: `~/Library/Application Support/netscout/` · Windows: `%APPDATA%\netscout\` | Standard per-OS locations. |
| Privileges | Capture requires root/BPF on macOS and Npcap on Windows. Detect at startup, explain clearly, degrade gracefully to passive (ARP-table) mode. | Don't crash, don't be mysterious. |
| Versioning | Internal working revisions `v0.1`, `v0.2`, … in `VERSION` + git tags. Published releases for others are whole numbers (`v1`, `v2`). **Never delete — revise up.** Keep a `CHANGELOG.md`. | Owner's convention. |

Repo location: `/Users/sethrichardson/Documents/Claude Code Projects/netscout`
(Note the space in the path — quote it in shell commands.)

---

## 1. What it does (scope)

### Sniffer (discovery)
- List network interfaces; let user pick one (or auto-pick the default route interface).
- **Passive capture** on the chosen interface, parsing:
  - ARP (request + reply) → IP ↔ MAC
  - DHCP (Discover/Request/ACK) → hostname, vendor class, requested IP, server IP
  - mDNS / Bonjour → hostname, service names (great for Dante, AirPlay, printers)
  - LLDP / CDP (if present) → switch name + port the device is on
  - Any IPv4 frame → at minimum "this MAC is alive and using this IP"
- **Active scan** (on demand): ARP sweep of the subnet + ICMP ping sweep, to wake up quiet devices.
- Maintain a live **device table**: IP, MAC, vendor, hostname, first seen, last seen, online/offline, interface, notes.
- **Conflict detection**: same IP seen with two different MACs within a window → flag it loudly.

### IPAM (inventory)
- Subnets: CIDR, name, VLAN tag, gateway, notes.
- Per-subnet view: every address shown as free / reserved / in-use / conflict.
- Reservations: assign an IP to a MAC with a label (e.g. "Dante — Yamaha CL5 primary") whether or not it's online.
- Device labels/tags, free-text notes, "expected vs. actual" (reservation says X, network says Y).
- Import/export: CSV + JSON. Import a client's IP sheet; export the live state for a show doc.

### MAC lookup
- Offline OUI lookup for every MAC seen. Handles 24-bit OUI, 28-bit MA-M, 36-bit MA-S.
- Flag locally-administered / randomized MACs (phones) so they aren't mistaken for gear.
- `netscout lookup <mac>` CLI command.
- `netscout update-oui` downloads the latest Wireshark `manuf` and replaces the bundled copy in the data dir (bundled copy remains as fallback).

### Out of scope for v1
- Full packet decode / Wireshark replacement.
- SNMP switch polling (nice for v2).
- Multi-user / server mode. This is a single-operator laptop tool.
- Linux builds (should "just work" from Go, but don't spend time on it).

---

## 2. Architecture

```
netscout/
├── cmd/netscout/          # main.go — CLI entry (cobra)
├── internal/
│   ├── capture/           # interface listing, pcap session, packet dispatch
│   ├── parse/             # arp.go, dhcp.go, mdns.go, lldp.go — each returns Observations
│   ├── scan/              # active ARP sweep + ICMP sweep
│   ├── oui/               # embedded manuf DB, lookup, updater
│   ├── store/             # SQLite schema, migrations, queries (devices, subnets, reservations, events)
│   ├── ipam/              # subnet math, address status, conflict logic
│   ├── engine/            # glue: capture → parse → store; emits events on a channel
│   └── web/               # http server, embedded static UI, JSON API, SSE for live updates
├── assets/oui/manuf       # bundled vendor DB
├── web/                   # HTML/CSS/JS source (vanilla + htmx or Alpine — no build step)
├── .github/workflows/     # CI: test + cross-platform release builds
├── CLAUDE.md
├── CHANGELOG.md
├── VERSION
└── README.md
```

**Data flow:** `capture` yields raw frames → `parse` turns each into zero or more `Observation{MAC, IP, Hostname, Source, Timestamp, Extra}` → `engine` upserts into `store` and runs conflict checks → `web` streams changes via SSE to the UI.

**Key types** (define early in `internal/model/` so every package shares them):

```go
type Device struct {
    MAC        string    // canonical lowercase aa:bb:cc:dd:ee:ff
    IPs        []string  // all IPs seen for this MAC
    Vendor     string
    Hostname   string
    FirstSeen  time.Time
    LastSeen   time.Time
    Online     bool
    Interface  string
    Label      string
    Notes      string
    Tags       []string
    Randomized bool      // locally-administered bit set
}

type Observation struct {
    MAC, IP, Hostname string
    Source            string // "arp","dhcp","mdns","lldp","ipv4","scan"
    Timestamp         time.Time
    Extra             map[string]string
}

type Subnet struct {
    ID      int64
    CIDR    string
    Name    string
    VLAN    int
    Gateway string
    Notes   string
}

type Reservation struct {
    SubnetID int64
    IP       string
    MAC      string
    Label    string
    Notes    string
}
```

---

## 3. Phases

Each phase: implement → `go test ./...` passes → `go build` on current OS → manual smoke test → bump `VERSION` (v0.x) → git tag → update `CHANGELOG.md` → commit. Don't start the next phase on a broken build.

### Phase 0 — Scaffold (v0.1)
- [ ] `git init`, `go mod init github.com/<owner>/netscout`
- [ ] Write `CLAUDE.md` (see §5), `README.md` stub, `VERSION` = `0.1`, `CHANGELOG.md`
- [ ] Add cobra CLI with `netscout version` and `netscout ifaces` (lists interfaces, marks default)
- [ ] GitHub Actions: `go vet`, `go test`, build matrix (macos-latest, windows-latest) that uploads binaries as artifacts
- [ ] `.gitignore` for the SQLite DB, local configs, build output
- **Done when:** `netscout ifaces` runs on macOS and Windows and the CI matrix is green.

### Phase 1 — Passive capture + ARP (v0.2)
- [ ] `capture` package: open pcap handle on an interface, BPF filter, graceful shutdown on Ctrl-C
- [ ] Privilege check: on macOS, detect lack of BPF access and print the exact fix (`sudo` or Wireshark's ChmodBPF). On Windows, detect missing Npcap and print the download link.
- [ ] `parse/arp.go` → Observations
- [ ] `store`: schema + migrations; `devices`, `observations`, `events` tables; upsert logic
- [ ] `netscout sniff -i <iface>` — live table in the terminal (use `bubbletea` or just a refreshing text table; keep it simple)
- **Done when:** running `sniff` on a busy LAN populates a device list with IP/MAC and last-seen updating live.

### Phase 2 — MAC vendor lookup (v0.3)
- [ ] Vendor the current Wireshark `manuf` file into `assets/oui/`; `go:embed` it
- [ ] Parser supporting 24/28/36-bit prefixes; longest-prefix match
- [ ] Randomized/locally-administered MAC detection
- [ ] Wire vendor into `store` upserts and the live table
- [ ] `netscout lookup <mac>` and `netscout update-oui`
- [ ] Unit tests with known OUIs (Audinate, Yamaha, Shure, Apple, QSC, Allen & Heath, Cisco)
- **Done when:** every device row shows a vendor or "unknown/randomized", and `lookup` works offline.

### Phase 3 — More parsers + active scan (v0.4)
- [ ] `parse/dhcp.go` (hostname opt 12, vendor class opt 60, requested IP opt 50)
- [ ] `parse/mdns.go` (A/PTR/SRV/TXT → hostname + services)
- [ ] `parse/lldp.go` (chassis ID, port ID, system name) — CDP optional
- [ ] `scan`: ARP sweep over a CIDR with rate limiting; ICMP sweep as fallback
- [ ] `netscout scan <cidr>`; `sniff` gets a `--scan` flag to sweep first, then listen
- [ ] Conflict detection in `engine`: same IP ↔ different MAC inside N seconds → `events` row + terminal warning
- **Done when:** a scan of a /24 completes in < 10s, hostnames appear for devices advertising via DHCP/mDNS, and an induced IP conflict is flagged.

### Phase 4 — IPAM core (v0.5)
- [ ] `subnets`, `reservations` tables + CRUD
- [ ] `ipam`: for a subnet, compute per-address status: free / reserved / in-use / reserved+in-use(match) / reserved+in-use(mismatch) / conflict
- [ ] CLI: `netscout subnet add|list|show`, `netscout reserve <ip> <mac> --label`, `netscout export --csv|--json`, `netscout import <file>`
- [ ] Device labels/notes/tags via CLI
- **Done when:** you can import a CSV of planned IPs, run a scan, and `subnet show` tells you exactly what matches, what's missing, and what's squatting.

### Phase 5 — Local web UI (v0.6)
- [ ] `web`: `net/http` server bound to `127.0.0.1`, random free port, auto-open browser; `--no-open` flag
- [ ] JSON API over `store` + SSE endpoint for live device updates
- [ ] Static UI embedded with `go:embed`; vanilla JS + htmx (no bundler). Pages:
  - **Live** — device table, live updating, filter/sort, click to edit label/notes
  - **Subnets** — grid/heatmap of a subnet's addresses colored by status
  - **Conflicts/Events** — log with timestamps
  - **Settings** — interface, scan interval, OUI update button
- [ ] `netscout ui` becomes the default command when run with no args
- **Done when:** double-clicking the binary opens a browser tab showing the live network.

### Phase 6 — Packaging + release (v1)
- [ ] CI release workflow on tag: macOS universal binary (arm64 + amd64 via `lipo`), Windows amd64 `.exe`; zip with README
- [ ] macOS: document that unsigned binaries need `xattr -d com.apple.quarantine` or right-click → Open. Signing/notarization is a follow-up, not a blocker.
- [ ] Windows: README states Npcap is required (link). Do **not** bundle the Npcap installer — redistribution has licensing terms.
- [ ] First-run checklist printed by the binary: permissions OK? Npcap OK? interface picked?
- [ ] Tag `v1`, write release notes from `CHANGELOG.md`
- **Done when:** a fresh macOS and a fresh Windows machine can download, run, and see devices within 2 minutes.

---

## 4. Testing rules
- Every parser has table-driven tests with real captured bytes (use small `.pcap` fixtures in `testdata/`; `gopacket/pcapgo` reads them without privileges, so CI can run them).
- `ipam` status logic is pure and fully unit-tested.
- `oui` lookup tested against known prefixes.
- Capture/scan code is integration-tested manually; don't fake root in CI.

## 5. `CLAUDE.md` contents (write this in Phase 0)
- Project summary + link to this PLAN.md
- Commands: `go build ./...`, `go test ./...`, `go run ./cmd/netscout sniff -i en0`
- Conventions: canonical MAC format lowercase colon-separated; all times UTC in DB, local in UI; errors wrapped with `fmt.Errorf("...: %w", err)`
- Versioning rule (decimal working revs, whole-number releases, never delete — revise up, CHANGELOG on every bump)
- "Before marking a phase done: build on the current OS, run tests, bump VERSION, tag, changelog, commit."
- Platform gotchas: macOS BPF permissions; Windows Npcap; Windows interface names are GUIDs — show friendly names via `pcap.FindAllDevs()` descriptions.

## 6. Known gotchas to plan around
- **macOS capture permissions**: libpcap needs `/dev/bpf*` access. Options: run with `sudo`, or install Wireshark's ChmodBPF launch daemon. Detect and explain; never silently fail.
- **Windows cross-compile from macOS works** for gopacket (runtime DLL loading), but **macOS must be built on macOS** (cgo + libpcap). CI matrix handles this.
- **Randomized MACs** (iOS/Android/Win11 private Wi-Fi addresses) will show as unknown vendor — label them, don't treat as bugs.
- **Dante/AES67 gear** often doesn't respond to ICMP but does respond to ARP and announces via mDNS — that's why ARP sweep + mDNS are both required.
- **VLANs**: 802.1Q-tagged frames need the VLAN layer stripped before parsing; record the tag on the observation.

## 7. Future (v2+) ideas — do not build now
- SNMP polling of managed switches → MAC-to-port table
- Dante-specific decoding (device names from Dante discovery)
- Export to a show-doc template / tech rider
- Scheduled scans + diff reports ("what changed since load-in?")
