// Package web serves the local browser UI and its JSON/SSE API on 127.0.0.1.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/engine"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/store"
	webassets "github.com/sethrichar/netscout/web"
)

// CaptureStatus describes the current capture session.
type CaptureStatus struct {
	Interface   capture.Interface `json:"interface"`
	Passive     bool              `json:"passive"`
	Hint        string            `json:"hint,omitempty"`
	Received    uint64            `json:"received"`
	Dropped     uint64            `json:"dropped"`
	Scanning    bool              `json:"scanning"`
	LastScan    time.Time         `json:"last_scan,omitempty"`
	ScanEvery   time.Duration     `json:"scan_every"`
	ScanCIDR    string            `json:"scan_cidr,omitempty"`
	OUISource   string            `json:"oui_source"`
	OUIEntries  int               `json:"oui_entries"`
	OUIUpdated  time.Time         `json:"oui_updated,omitempty"`
	DataDir     string            `json:"data_dir"`
	StartedAt   time.Time         `json:"started_at"`
	Version     string            `json:"version"`
	OnlineAfter time.Duration     `json:"online_window"`
}

// Controller is what the server needs from the running capture runtime.
type Controller interface {
	Status() CaptureStatus
	Interfaces() ([]capture.Interface, error)
	SwitchInterface(name string) error
	Scan(ctx context.Context, cidr string) error
	SetScanInterval(ctx context.Context, every time.Duration, cidr string)
	UpdateOUI(ctx context.Context) (oui.UpdateResult, error)
	OUI() *oui.DB
}

// Server is the HTTP front end.
type Server struct {
	eng    *engine.Engine
	store  *store.Store
	ctl    Controller
	logger *log.Logger
	mux    *http.ServeMux
	ln     net.Listener
	srv    *http.Server
}

// Options configure Listen.
type Options struct {
	Port   int // 0 = random free port
	Host   string
	Logger *log.Logger
}

// New builds a server; call Listen to bind it.
func New(eng *engine.Engine, st *store.Store, ctl Controller, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{eng: eng, store: st, ctl: ctl, logger: logger, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Listen binds to 127.0.0.1 and returns the URL. The server only ever listens
// on loopback: this is a single-operator tool with no authentication.
func (s *Server) Listen(opts Options) (string, error) {
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, opts.Port))
	if err != nil {
		return "", fmt.Errorf("listening on %s:%d: %w", host, opts.Port, err)
	}
	s.ln = ln
	s.srv = &http.Server{Handler: s.hostCheck(s.mux), ReadHeaderTimeout: 10 * time.Second}
	return "http://" + ln.Addr().String(), nil
}

// Serve runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("Listen first")
	}
	errc := make(chan error, 1)
	go func() { errc <- s.srv.Serve(s.ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Handler exposes the mux for tests.
func (s *Server) Handler() http.Handler { return s.hostCheck(s.mux) }

// hostCheck rejects requests whose Host header is not loopback, which defeats
// DNS-rebinding attacks against the unauthenticated local API.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && !strings.HasSuffix(host, ".localhost") {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	static, err := fs.Sub(webassets.Static, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(static))
	s.mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || !strings.Contains(r.URL.Path, ".") {
			r.URL.Path = "/"
		}
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	}))

	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/ifaces", s.handleIfaces)
	s.mux.HandleFunc("POST /api/capture", s.handleCapture)
	s.mux.HandleFunc("GET /api/stream", s.handleStream)

	s.mux.HandleFunc("GET /api/devices", s.handleDevices)
	s.mux.HandleFunc("GET /api/devices/{mac}", s.handleDevice)
	s.mux.HandleFunc("PATCH /api/devices/{mac}", s.handleDevicePatch)
	s.mux.HandleFunc("DELETE /api/devices/{mac}", s.handleDeviceDelete)
	s.mux.HandleFunc("GET /api/lookup", s.handleLookup)

	s.mux.HandleFunc("GET /api/events", s.handleEvents)
	s.mux.HandleFunc("POST /api/conflicts/clear", s.handleClearConflict)

	s.mux.HandleFunc("GET /api/subnets", s.handleSubnets)
	s.mux.HandleFunc("POST /api/subnets", s.handleSubnetCreate)
	s.mux.HandleFunc("PATCH /api/subnets/{id}", s.handleSubnetPatch)
	s.mux.HandleFunc("DELETE /api/subnets/{id}", s.handleSubnetDelete)
	s.mux.HandleFunc("GET /api/subnets/{id}/map", s.handleSubnetMap)
	s.mux.HandleFunc("POST /api/reservations", s.handleReservationUpsert)
	s.mux.HandleFunc("DELETE /api/reservations/{id}", s.handleReservationDelete)

	s.mux.HandleFunc("GET /api/export", s.handleExport)
	s.mux.HandleFunc("POST /api/import", s.handleImport)
	s.mux.HandleFunc("POST /api/scan", s.handleScan)
	s.mux.HandleFunc("POST /api/scan/schedule", s.handleScanSchedule)
	s.mux.HandleFunc("POST /api/oui/update", s.handleOUIUpdate)
}

// --- helpers -----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// OpenBrowser launches the default browser at url (best effort).
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("opening browser: %w", err)
	}
	go cmd.Wait()
	return nil
}
