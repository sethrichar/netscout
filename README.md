# netscout

LAN sniffer + IPAM with offline MAC vendor lookup, built for show-site / AV /
Dante networks. One binary, macOS and Windows.

- **Discover** everything on the switch: passive capture of ARP, DHCP, mDNS/Bonjour,
  LLDP/CDP, plus on-demand ARP/ICMP sweeps.
- **Identify** devices by MAC vendor from the bundled Wireshark OUI database —
  fully offline. Randomised phone MACs are flagged, not mislabelled.
- **Track** IP ↔ MAC assignments, flag IP conflicts loudly, keep subnets and
  reservations, import/export CSV + JSON.
- **See it live** in a local web UI (phase 5) or a terminal table.

> Status: in active development — see [CHANGELOG.md](CHANGELOG.md) and
> [PLAN.md](PLAN.md) for the roadmap.

## Quick start

```sh
netscout ifaces              # pick an interface (default route marked *)
sudo netscout sniff -i en0   # live device table (macOS needs BPF access)
netscout lookup 00:1d:c1:12:34:56
```

### Requirements

- **macOS**: packet capture needs `/dev/bpf*` access — run with `sudo` or
  install Wireshark's ChmodBPF component once.
- **Windows**: install [Npcap](https://npcap.com/#download) (WinPcap API
  compatible mode). netscout does not bundle it.

## Build from source

```sh
go build -o netscout ./cmd/netscout
```

Linux needs `libpcap-dev`. macOS and Windows need nothing extra at build time.

## License

MIT. Bundled vendor data is from the Wireshark project (GPL-2.0-or-later data
file, redistributed unmodified).
