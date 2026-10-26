# netscout on macOS

## 1. Unblock the binary (unsigned builds)

macOS quarantines downloaded binaries that are not notarized. Either:

```sh
xattr -d com.apple.quarantine ./netscout
```

or right-click `netscout` in Finder → **Open** → **Open** once. After that it
runs normally.

## 2. Give it capture access

Packet capture needs read access to `/dev/bpf*`. Pick one:

- **Quick:** run with `sudo`:
  ```sh
  sudo ./netscout
  ```
- **Permanent, no sudo:** install [Wireshark](https://www.wireshark.org/download.html)
  and accept the **ChmodBPF** component during install, then log out and back
  in. netscout (and any other capture tool) then works as your normal user.

Without capture access netscout still runs in *passive mode* (reads the OS ARP
table) and tells you exactly what to do.

## 3. Run it

```sh
./netscout            # opens the web UI in your browser
./netscout sniff      # live table in the terminal instead
./netscout doctor     # checks permissions, interface, vendor DB
```

Data lives in `~/Library/Application Support/netscout/`.
