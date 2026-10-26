// Package store persists devices, observations, events and IPAM data in a
// single SQLite file (pure-Go driver, no cgo).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sethrichar/netscout/internal/config"
	"github.com/sethrichar/netscout/internal/model"
)

// Store wraps the SQLite connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies migrations.
// Use ":memory:" for an ephemeral store (tests).
func Open(path string) (*Store, error) {
	dsn := path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared"
	} else {
		// SQLite parses file: URIs, so characters with URI meaning in the path
		// (%, ?, #) must be escaped; slashes and backslashes stay as they are
		// so Windows paths keep working.
		escaped := strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23").Replace(path)
		dsn = "file:" + escaped + "?" + url.Values{
			"_pragma": {"journal_mode(WAL)", "busy_timeout(5000)", "foreign_keys(1)", "synchronous(NORMAL)"},
		}.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %q: %w", path, err)
	}
	// SQLite is single-writer; serialising through one connection avoids
	// SQLITE_BUSY churn and keeps the in-memory variant coherent.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" {
		config.FixOwnershipOfDBFiles(path)
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle for ad-hoc queries (exports, tests).
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	var ver int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}
	for i := ver; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("applying migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("setting schema version %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", i+1, err)
		}
	}
	return nil
}

// --- time / json helpers -----------------------------------------------------

// tsLayout is fixed-width so string comparison in SQL (MIN/MAX/ORDER BY)
// matches chronological order; RFC3339Nano trims trailing zeros and does not.
const tsLayout = "2006-01-02T15:04:05.000000000Z07:00"

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(tsLayout)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s) // accepts the fixed-width layout too
	if err != nil {
		return time.Time{}
	}
	return t
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func tagsJSON(tags []string) string {
	if tags == nil {
		tags = []string{}
	}
	return toJSON(tags)
}

func parseTags(s string) []string {
	var tags []string
	if err := json.Unmarshal([]byte(s), &tags); err != nil || tags == nil {
		return []string{}
	}
	return tags
}

func parseMap(s string) map[string]string {
	m := map[string]string{}
	if s == "" {
		return m
	}
	_ = json.Unmarshal([]byte(s), &m)
	return m
}

// --- meta --------------------------------------------------------------------

// SetMeta stores a key/value setting.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("setting meta %q: %w", key, err)
	}
	return nil
}

// GetMeta returns a setting or "" when unset.
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading meta %q: %w", key, err)
	}
	return v, nil
}

// --- devices -----------------------------------------------------------------

// IPSeen is one address a device has used, with its observation window.
type IPSeen struct {
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
}

// SaveObserved upserts the fields the engine learns from the network. User
// fields (label, notes, tags) are never touched by this call so concurrent
// edits are not clobbered.
func (s *Store) SaveObserved(d *model.Device, ips []IPSeen) error {
	return s.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
INSERT INTO devices (mac, vendor, vendor_short, hostname, first_seen, last_seen, online, iface, randomized)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(mac) DO UPDATE SET
    vendor       = excluded.vendor,
    vendor_short = excluded.vendor_short,
    hostname     = excluded.hostname,
    first_seen   = CASE WHEN devices.first_seen = '' THEN excluded.first_seen ELSE MIN(devices.first_seen, excluded.first_seen) END,
    last_seen    = CASE WHEN devices.last_seen = '' THEN excluded.last_seen ELSE MAX(devices.last_seen, excluded.last_seen) END,
    online       = excluded.online,
    iface        = excluded.iface,
    randomized   = excluded.randomized`,
			d.MAC, d.Vendor, d.VendorShort, d.Hostname, fmtTime(d.FirstSeen), fmtTime(d.LastSeen), b2i(d.Online), d.Interface, b2i(d.Randomized))
		if err != nil {
			return fmt.Errorf("upserting device %s: %w", d.MAC, err)
		}
		for _, ip := range ips {
			if _, err := tx.Exec(`
INSERT INTO device_ips (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)
ON CONFLICT(mac, ip) DO UPDATE SET
    first_seen = MIN(device_ips.first_seen, excluded.first_seen),
    last_seen  = MAX(device_ips.last_seen, excluded.last_seen)`,
				d.MAC, ip.IP, fmtTime(ip.FirstSeen), fmtTime(ip.LastSeen)); err != nil {
				return fmt.Errorf("upserting ip %s for %s: %w", ip.IP, d.MAC, err)
			}
		}
		// Attrs are replaced as a set so keys removed in memory (cleared
		// conflicts, a previous "self" marker) disappear from disk too.
		if _, err := tx.Exec(`DELETE FROM device_attrs WHERE mac = ?`, d.MAC); err != nil {
			return fmt.Errorf("clearing attrs for %s: %w", d.MAC, err)
		}
		now := fmtTime(time.Now())
		for k, v := range d.Attrs {
			if _, err := tx.Exec(`
INSERT INTO device_attrs (mac, key, value, updated_at) VALUES (?, ?, ?, ?)
ON CONFLICT(mac, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
				d.MAC, k, v, now); err != nil {
				return fmt.Errorf("upserting attr %s for %s: %w", k, d.MAC, err)
			}
		}
		return nil
	})
}

// SetUserFields updates label/notes/tags, creating a placeholder device row if
// the MAC has never been observed (so labels can be prepared ahead of a show).
func (s *Store) SetUserFields(mac string, label, notes *string, tags []string) error {
	return s.tx(func(tx *sql.Tx) error {
		// Placeholder rows carry empty timestamps: "never seen".
		if _, err := tx.Exec(`INSERT OR IGNORE INTO devices (mac, first_seen, last_seen) VALUES (?, '', '')`, mac); err != nil {
			return fmt.Errorf("ensuring device %s: %w", mac, err)
		}
		if label != nil {
			if _, err := tx.Exec(`UPDATE devices SET label = ? WHERE mac = ?`, *label, mac); err != nil {
				return fmt.Errorf("setting label: %w", err)
			}
		}
		if notes != nil {
			if _, err := tx.Exec(`UPDATE devices SET notes = ? WHERE mac = ?`, *notes, mac); err != nil {
				return fmt.Errorf("setting notes: %w", err)
			}
		}
		if tags != nil {
			if _, err := tx.Exec(`UPDATE devices SET tags = ? WHERE mac = ?`, tagsJSON(tags), mac); err != nil {
				return fmt.Errorf("setting tags: %w", err)
			}
		}
		return nil
	})
}

// SetOnline flips the online flag (used by offline sweeps).
func (s *Store) SetOnline(mac string, online bool) error {
	if _, err := s.db.Exec(`UPDATE devices SET online = ? WHERE mac = ?`, b2i(online), mac); err != nil {
		return fmt.Errorf("setting online for %s: %w", mac, err)
	}
	return nil
}

// DeleteDevice removes a device and its IPs/attrs.
func (s *Store) DeleteDevice(mac string) error {
	if _, err := s.db.Exec(`DELETE FROM devices WHERE mac = ?`, mac); err != nil {
		return fmt.Errorf("deleting device %s: %w", mac, err)
	}
	return nil
}

// GetDevice returns one device or nil when unknown.
func (s *Store) GetDevice(mac string) (*model.Device, error) {
	devs, err := s.listDevices(`WHERE mac = ?`, mac)
	if err != nil || len(devs) == 0 {
		return nil, err
	}
	return &devs[0], nil
}

// ListDevices returns every device with IPs (most recent first) and attrs.
func (s *Store) ListDevices() ([]model.Device, error) {
	return s.listDevices("")
}

// ListDeviceIPs returns the full IP history for one MAC.
func (s *Store) ListDeviceIPs(mac string) ([]IPSeen, error) {
	rows, err := s.db.Query(`SELECT ip, first_seen, last_seen FROM device_ips WHERE mac = ? ORDER BY last_seen DESC`, mac)
	if err != nil {
		return nil, fmt.Errorf("listing ips for %s: %w", mac, err)
	}
	defer rows.Close()
	var out []IPSeen
	for rows.Next() {
		var ip IPSeen
		var f, l string
		if err := rows.Scan(&ip.IP, &f, &l); err != nil {
			return nil, err
		}
		ip.FirstSeen, ip.LastSeen = parseTime(f), parseTime(l)
		out = append(out, ip)
	}
	return out, rows.Err()
}

func (s *Store) listDevices(where string, args ...any) ([]model.Device, error) {
	rows, err := s.db.Query(`
SELECT mac, vendor, vendor_short, hostname, first_seen, last_seen, online, iface, label, notes, tags, randomized
FROM devices `+where+` ORDER BY last_seen DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}
	defer rows.Close()
	var devs []model.Device
	idx := map[string]int{}
	for rows.Next() {
		var d model.Device
		var first, last, tags string
		var online, randomized int
		if err := rows.Scan(&d.MAC, &d.Vendor, &d.VendorShort, &d.Hostname, &first, &last, &online, &d.Interface, &d.Label, &d.Notes, &tags, &randomized); err != nil {
			return nil, fmt.Errorf("scanning device: %w", err)
		}
		d.FirstSeen, d.LastSeen = parseTime(first), parseTime(last)
		d.Online, d.Randomized = online == 1, randomized == 1
		d.Tags = parseTags(tags)
		d.IPs = []string{}
		d.Attrs = map[string]string{}
		idx[d.MAC] = len(devs)
		devs = append(devs, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return devs, nil
	}

	ipRows, err := s.db.Query(`SELECT mac, ip FROM device_ips ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing device ips: %w", err)
	}
	for ipRows.Next() {
		var mac, ip string
		if err := ipRows.Scan(&mac, &ip); err != nil {
			ipRows.Close()
			return nil, err
		}
		if i, ok := idx[mac]; ok {
			devs[i].IPs = append(devs[i].IPs, ip)
		}
	}
	ipRows.Close()

	attrRows, err := s.db.Query(`SELECT mac, key, value FROM device_attrs`)
	if err != nil {
		return nil, fmt.Errorf("listing device attrs: %w", err)
	}
	for attrRows.Next() {
		var mac, k, v string
		if err := attrRows.Scan(&mac, &k, &v); err != nil {
			attrRows.Close()
			return nil, err
		}
		if i, ok := idx[mac]; ok {
			devs[i].Attrs[k] = v
		}
	}
	attrRows.Close()
	return devs, nil
}

// --- observations ------------------------------------------------------------

// AddObservation appends a raw observation row.
func (s *Store) AddObservation(o model.Observation) error {
	_, err := s.db.Exec(`INSERT INTO observations (ts, mac, ip, hostname, source, iface, vlan, extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		fmtTime(o.Timestamp), o.MAC, o.IP, o.Hostname, o.Source, o.Interface, o.VLAN, toJSON(o.Extra))
	if err != nil {
		return fmt.Errorf("inserting observation: %w", err)
	}
	return nil
}

// ListObservations returns the newest observations for a MAC ("" = all).
func (s *Store) ListObservations(mac string, limit int) ([]model.Observation, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT ts, mac, ip, hostname, source, iface, vlan, extra FROM observations `
	var args []any
	if mac != "" {
		q += `WHERE mac = ? `
		args = append(args, mac)
	}
	q += `ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing observations: %w", err)
	}
	defer rows.Close()
	var out []model.Observation
	for rows.Next() {
		var o model.Observation
		var ts, extra string
		if err := rows.Scan(&ts, &o.MAC, &o.IP, &o.Hostname, &o.Source, &o.Interface, &o.VLAN, &extra); err != nil {
			return nil, err
		}
		o.Timestamp = parseTime(ts)
		o.Extra = parseMap(extra)
		out = append(out, o)
	}
	return out, rows.Err()
}

// PruneObservations deletes observation rows older than the cutoff.
func (s *Store) PruneObservations(olderThan time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM observations WHERE ts < ?`, fmtTime(olderThan))
	if err != nil {
		return 0, fmt.Errorf("pruning observations: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// --- events ------------------------------------------------------------------

// AddEvent stores an event and fills in its ID.
func (s *Store) AddEvent(e *model.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	res, err := s.db.Exec(`INSERT INTO events (ts, kind, mac, ip, message, details) VALUES (?, ?, ?, ?, ?, ?)`,
		fmtTime(e.Time), e.Kind, e.MAC, e.IP, e.Message, toJSON(e.Details))
	if err != nil {
		return fmt.Errorf("inserting event: %w", err)
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// EventFilter narrows ListEvents.
type EventFilter struct {
	Kind    string
	MAC     string
	Since   time.Time
	AfterID int64
	Limit   int
}

// ListEvents returns events newest-first (or oldest-first when AfterID is set,
// which is what a live tail wants).
func (s *Store) ListEvents(f EventFilter) ([]model.Event, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	var where []string
	var args []any
	if f.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.MAC != "" {
		where = append(where, "mac = ?")
		args = append(args, f.MAC)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, fmtTime(f.Since))
	}
	order := "DESC"
	if f.AfterID > 0 {
		where = append(where, "id > ?")
		args = append(args, f.AfterID)
		order = "ASC"
	}
	q := `SELECT id, ts, kind, mac, ip, message, details FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id " + order + " LIMIT ?"
	args = append(args, f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing events: %w", err)
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var ts, details string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.MAC, &e.IP, &e.Message, &details); err != nil {
			return nil, err
		}
		e.Time = parseTime(ts)
		e.Details = parseMap(details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- helpers -----------------------------------------------------------------

func (s *Store) tx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
