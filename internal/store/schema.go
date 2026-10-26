package store

// migrations are applied in order; PRAGMA user_version records the count.
var migrations = []string{
	// 1: devices, device_ips, device_attrs, observations, events, meta
	`
CREATE TABLE IF NOT EXISTS devices (
    mac          TEXT PRIMARY KEY,
    vendor       TEXT NOT NULL DEFAULT '',
    vendor_short TEXT NOT NULL DEFAULT '',
    hostname     TEXT NOT NULL DEFAULT '',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    online       INTEGER NOT NULL DEFAULT 0,
    iface        TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    tags         TEXT NOT NULL DEFAULT '[]',
    randomized   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_ips (
    mac        TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);
CREATE INDEX IF NOT EXISTS device_ips_ip ON device_ips(ip);
CREATE TABLE IF NOT EXISTS device_attrs (
    mac        TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (mac, key)
);
CREATE TABLE IF NOT EXISTS observations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    mac      TEXT NOT NULL,
    ip       TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    source   TEXT NOT NULL,
    iface    TEXT NOT NULL DEFAULT '',
    vlan     INTEGER NOT NULL DEFAULT 0,
    extra    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS observations_mac_ts ON observations(mac, ts);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    kind    TEXT NOT NULL,
    mac     TEXT NOT NULL DEFAULT '',
    ip      TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`,
	// 2: IPAM — subnets and reservations
	`
CREATE TABLE IF NOT EXISTS subnets (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr    TEXT NOT NULL UNIQUE,
    name    TEXT NOT NULL DEFAULT '',
    vlan    INTEGER NOT NULL DEFAULT 0,
    gateway TEXT NOT NULL DEFAULT '',
    notes   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS reservations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet_id INTEGER NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,
    ip        TEXT NOT NULL,
    mac       TEXT NOT NULL DEFAULT '',
    label     TEXT NOT NULL DEFAULT '',
    notes     TEXT NOT NULL DEFAULT '',
    UNIQUE (subnet_id, ip)
);
CREATE INDEX IF NOT EXISTS reservations_mac ON reservations(mac);
`,
}
