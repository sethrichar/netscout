# netscout — notes for Claude Code

LAN sniffer + IPAM + offline MAC vendor lookup for show-site / AV / Dante
networks. Single static Go binary, macOS + Windows. The full execution plan is
in [PLAN.md](PLAN.md); read it before changing scope.

## Commands

```sh
go build ./...                       # build everything
go test ./...                        # unit tests (no root needed)
go vet ./...
go run ./cmd/netscout ifaces         # list interfaces, default marked *
sudo go run ./cmd/netscout sniff -i en0   # live capture (needs BPF/Npcap)
go run ./cmd/netscout lookup 00:1d:c1:aa:bb:cc
```

Linux dev boxes need `libpcap-dev`; macOS has libpcap built in; Windows needs
Npcap at runtime (no cgo — `wpcap.dll` is loaded dynamically).

## Layout

- `cmd/netscout` — main. `internal/cli` — cobra commands, one file per command.
- `internal/model` — shared types (Device, Observation, Subnet, Reservation, Event).
- `internal/capture` — interface listing, pcap sessions, privilege hints.
- `internal/parse` — one file per protocol; each returns `[]model.Observation`.
- `internal/scan` — active ARP / ICMP sweeps.
- `internal/oui` — Wireshark `manuf` parser + lookup + updater. Bundled data in `assets/oui/manuf`.
- `internal/store` — SQLite (modernc, pure Go). Migrations in `schema.go`.
- `internal/ipam` — pure subnet / address-status logic.
- `internal/engine` — capture → parse → store glue, conflict detection, event fan-out.
- `internal/web` — HTTP API + SSE; static UI lives in `web/static` (vanilla JS, no build step).

## Conventions

- MACs are canonical lowercase colon-separated (`aa:bb:cc:dd:ee:ff`) everywhere;
  normalise at the edge with `model.NormalizeMAC`.
- Times are UTC in the DB and on the wire (JSON), local in the UI/terminal.
- Wrap errors: `fmt.Errorf("doing x: %w", err)`. No bare `err` returns from
  package boundaries without context.
- Parsers are pure: packet in, observations out. No DB access in `parse`.
- Keep deps minimal. Decision log: `github.com/gopacket/gopacket` (maintained
  fork of google/gopacket; identical API, current Go support), cobra, modernc
  sqlite, `golang.org/x/net` (ICMP only).

## Versioning (owner's rule)

- Working revisions are decimals in `VERSION` (`0.1`, `0.2`, …) with matching
  git tags `v0.1`, `v0.2`. Published releases are whole numbers (`v1`, `v2`).
- **Never delete or rewrite a version — revise up.** Every bump gets a
  `CHANGELOG.md` entry.
- Before marking a phase done: build on the current OS, `go test ./...`, bump
  `VERSION`, update `CHANGELOG.md`, commit, tag.

## Platform gotchas

- macOS capture needs `/dev/bpf*` access: `sudo`, or Wireshark's ChmodBPF.
  `capture.PrivilegeHint` explains this; never fail silently.
- Windows needs Npcap. Call `pcap.LoadWinPCAP()` (via `capture.checkRuntime`)
  before any pcap call or the process crashes. Interface names are
  `\Device\NPF_{GUID}`; show descriptions from `pcap.FindAllDevs()` instead.
- macOS binaries must be built on macOS (cgo). Windows cross-compiles fine
  with `CGO_ENABLED=0`.
- 802.1Q frames: strip the VLAN layer before parsing and record the tag.
- Randomised MACs (phones) are expected to show no vendor — label, don't "fix".
