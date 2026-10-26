# Third-party notices

## Wireshark vendor (OUI) database

`assets/oui/manuf` is derived from the Wireshark project's
`epan/manuf-data.c`, which assembles the IEEE public OUI / CID / IAB / MA-M /
MA-S registries. It is converted into Wireshark's classic tab-separated
`manuf` text format by `tools/manufconv` (a format change only; the vendor
data itself is not edited) and embedded in the netscout binary.

- Source: <https://gitlab.com/wireshark/wireshark> (`epan/manuf-data.c`)
- Licence of the data file: GPL-2.0-or-later (see the SPDX header retained at
  the top of `assets/oui/manuf`)
- `netscout update-oui` downloads the current `manuf` file from
  <https://www.wireshark.org/download/automated/data/manuf> (or converts the
  current `manuf-data.c` from the GitHub mirror) into the data directory.

## Go modules

netscout links the following Go modules; each carries its own licence in the
module cache / `go.sum`:

- github.com/gopacket/gopacket — BSD-3-Clause
- github.com/spf13/cobra, github.com/spf13/pflag — Apache-2.0 / BSD-3-Clause
- modernc.org/sqlite (and its modernc.org dependencies) — BSD-3-Clause
- golang.org/x/net, golang.org/x/sys, golang.org/x/term — BSD-3-Clause
- github.com/mattn/go-isatty — MIT

## Npcap (Windows)

netscout does **not** bundle Npcap. Windows users install it separately from
<https://npcap.com>; Npcap's own licence applies.
