package oui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sethrichar/netscout/assets"
	"github.com/sethrichar/netscout/internal/config"
)

// MinEntries guards against a truncated or wrong download replacing good data.
const MinEntries = 30000

// Embedded parses the database bundled in the binary.
func Embedded() (*DB, error) {
	db, err := Parse(bytes.NewReader(assets.Manuf))
	if err != nil {
		return nil, fmt.Errorf("parsing embedded manuf: %w", err)
	}
	db.Source = "embedded"
	return db, nil
}

// Load prefers an updated copy in dataDir (written by Update) and falls back to
// the embedded database. A corrupt updated copy is ignored, not fatal.
func Load(dataDir string) (*DB, error) {
	if dataDir != "" {
		path := config.ManufPath(dataDir)
		if f, err := os.Open(path); err == nil {
			db, perr := Parse(f)
			f.Close()
			if perr == nil && db.Len() >= MinEntries {
				db.Source = path
				return db, nil
			}
		}
	}
	return Embedded()
}

// Sources tried by Update, in order.
var (
	ManufURL   = "https://www.wireshark.org/download/automated/data/manuf"
	CSourceURL = "https://raw.githubusercontent.com/wireshark/wireshark/master/epan/manuf-data.c"
)

// UpdateResult reports what Update did.
type UpdateResult struct {
	Path    string
	Source  string
	Entries int
}

// Update downloads the latest vendor data into dataDir/manuf. It tries the
// Wireshark text file first and falls back to converting the C source from
// the GitHub mirror. The bundled copy is never modified.
func Update(ctx context.Context, dataDir string, client *http.Client) (UpdateResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	var db *DB
	var src string
	var errs []error

	if body, err := fetch(ctx, client, ManufURL); err == nil {
		if d, perr := Parse(bytes.NewReader(body)); perr == nil && d.Len() >= MinEntries {
			db, src = d, ManufURL
		} else if perr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ManufURL, perr))
		} else {
			errs = append(errs, fmt.Errorf("%s: only %d entries", ManufURL, d.Len()))
		}
	} else {
		errs = append(errs, err)
	}
	if db == nil {
		if body, err := fetch(ctx, client, CSourceURL); err == nil {
			if d, perr := ParseCSource(bytes.NewReader(body)); perr == nil && d.Len() >= MinEntries {
				db, src = d, CSourceURL
			} else if perr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", CSourceURL, perr))
			} else {
				errs = append(errs, fmt.Errorf("%s: only %d entries", CSourceURL, d.Len()))
			}
		} else {
			errs = append(errs, err)
		}
	}
	if db == nil {
		return UpdateResult{}, fmt.Errorf("could not fetch vendor data: %v", errs)
	}

	path := config.ManufPath(dataDir)
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("writing %s: %w", tmp, err)
	}
	header := fmt.Sprintf("Wireshark manuf — downloaded by netscout update-oui on %s from %s", time.Now().UTC().Format(time.RFC3339), src)
	if err := db.Write(f, header); err != nil {
		f.Close()
		os.Remove(tmp)
		return UpdateResult{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return UpdateResult{}, fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return UpdateResult{}, fmt.Errorf("replacing %s: %w", path, err)
	}
	return UpdateResult{Path: path, Source: src, Entries: db.Len()}, nil
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netscout (+https://github.com/sethrichar/netscout)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	return body, nil
}

// UpdatedAt returns the modification time of an updated copy, or zero.
func UpdatedAt(dataDir string) time.Time {
	st, err := os.Stat(filepath.Join(dataDir, "manuf"))
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}
