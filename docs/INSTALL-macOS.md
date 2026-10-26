# netscout on macOS

## 1. Unblock the binary (unsigned builds)

macOS quarantines downloaded binaries that are not notarized. Either remove
the flag:

```sh
xattr -d com.apple.quarantine ./netscout
```

or launch it once, let macOS block it, then open **System Settings → Privacy &
Security**, scroll to the message about netscout and click **Open Anyway**,
then launch again. (The old right-click → Open trick no longer works on macOS
15 and later. Code signing / notarization is the real fix and is on the list.)

## 2. Give it capture access

Packet capture needs read access to `/dev/bpf*`. Pick one:

- **Recommended — permanent, no sudo:** install
  [Wireshark](https://www.wireshark.org/download.html) and accept the
  **ChmodBPF** component during install, then log out and back in. netscout
  (and any other capture tool) then works as your normal user.
- **Quick:** prefix the capturing commands with `sudo`:
  ```sh
  sudo ./netscout
  sudo ./netscout sniff
  sudo ./netscout scan
  ```
  netscout hands its data directory and database back to your user when run
  under sudo, so the read-only commands (`devices`, `subnet show`, `export`,
  `lookup`) keep working without it.

Without capture access netscout still runs in *passive mode* (reads the OS ARP
table) and tells you exactly what to do.

## 3. Run it

```sh
./netscout doctor     # checks permissions, interface, vendor DB
./netscout            # opens the web UI in your browser
./netscout sniff      # live table in the terminal instead
```

Data lives in `~/Library/Application Support/netscout/`.
