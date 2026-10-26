# netscout on Windows

## 1. Install Npcap (required)

netscout uses Npcap for packet capture and does **not** bundle it (Npcap's
licence doesn't allow redistribution).

1. Download Npcap from <https://npcap.com/#download>.
2. Run the installer with its default options. Leave **"Restrict Npcap
   driver's access to Administrators only"** *unchecked* (the default) so
   netscout works from a normal terminal; if you check it, run netscout from
   an Administrator terminal instead.

## 2. Run it

Double-click `netscout.exe` — it opens the web UI in your browser. Or from a
terminal:

```powershell
.\netscout.exe            # web UI
.\netscout.exe sniff      # live table in the terminal
.\netscout.exe doctor     # checks Npcap, permissions, interface, vendor DB
```

Windows SmartScreen may warn about an unknown publisher the first time: choose
**More info → Run anyway**.

Data lives in `%APPDATA%\netscout\`.

Interface names on Windows are GUIDs (`\Device\NPF_{…}`); netscout shows the
friendly adapter description next to them in `netscout ifaces` and in the UI.
