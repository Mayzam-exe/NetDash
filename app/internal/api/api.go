package api

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netdash/internal/engine"
)

//go:embed all:dist
var distFS embed.FS

type Server struct {
	e     *engine.Engine
	token string // optional bearer token; "" disables auth
}

// New builds the HTTP API. token, when non-empty, requires every /api/* request
// to carry it (see withAuth); an empty token keeps the historical behaviour.
func New(e *engine.Engine, token string) *Server { return &Server{e: e, token: token} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("POST /api/devices/{id}", s.handleDevicePatch)
	mux.HandleFunc("DELETE /api/devices/{id}", s.handleDeviceDelete)
	mux.HandleFunc("POST /api/devices/{id}/ping", s.handleDevicePing)
	mux.HandleFunc("POST /api/devices/{id}/traceroute", s.handleDeviceTraceroute)
	mux.HandleFunc("POST /api/devices/{id}/dnslookup", s.handleDeviceDNSLookup)
	mux.HandleFunc("POST /api/devices/{id}/renew-dhcp", s.handleDeviceRenewDHCP)
	mux.HandleFunc("POST /api/devices/{id}/restart-radio", s.handleDeviceRestartRadio)
	mux.HandleFunc("POST /api/devices/{id}/scan", s.handleDeviceScan)
	mux.HandleFunc("GET /api/devices/{id}/scan", s.handleDeviceScanLast)
	mux.HandleFunc("GET /api/alerts", s.handleAlerts)
	mux.HandleFunc("POST /api/alerts/{id}/ack", s.handleAck)
	mux.HandleFunc("POST /api/alerts/clear", s.handleClearAlerts)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/devices/{id}/intel", s.handleDeviceIntel)
	mux.HandleFunc("GET /api/spoof-rules", s.handleSpoofList)
	mux.HandleFunc("POST /api/spoof-rules", s.handleSpoofAdd)
	mux.HandleFunc("DELETE /api/spoof-rules/{id}", s.handleSpoofDel)
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("PUT /api/settings", s.handlePutSettings)
	mux.HandleFunc("GET /api/stream", s.handleStream)

	// static frontend (embedded), SPA fallback
	static, err := fs.Sub(distFS, "dist")
	if err != nil {
		log.Printf("embed dist: %v", err)
	}
	fileServer := http.FileServer(http.FS(static))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(static, p); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// SPA fallback
		b, err := fs.ReadFile(static, "index.html")
		if err != nil {
			http.Error(w, "frontend not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	return withSecurityHeaders(withAuth(mux, s.token))
}

// withAuth optionally enforces a bearer token on every /api/* request. An empty
// token disables auth (the default 127.0.0.1 binding). When set, the token is
// accepted as "Authorization: Bearer <t>" or as "?token=<t>" — the query form
// exists so the EventSource SSE stream, which cannot set headers, still works.
func withAuth(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		got := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			got = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		} else if q := r.URL.Query().Get("token"); q != "" {
			got = q
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders applies hardening headers to every response. (The previous
// helper was misnamed withCORS: it never set any CORS header.)
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// The SPA uses inline style attributes, so style-src needs
		// 'unsafe-inline'; scripts stay restricted to the same-origin bundles.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; script-src 'self'; "+
				"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.e.Snapshot().Status)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"devices": s.e.Snapshot().Devices})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"alerts": s.e.Snapshot().Alerts})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.e.Snapshot().History)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.e.Settings())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	// Merge semantics: only fields present in the body are updated.
	st := s.e.Settings()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &st); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if net.ParseIP(strings.TrimSpace(st.GatewayIP)) == nil {
		http.Error(w, "gatewayIp must be a valid IP address", http.StatusBadRequest)
		return
	}
	if net.ParseIP(strings.TrimSpace(st.WANIP)) == nil {
		http.Error(w, "wanIp must be a valid IP address", http.StatusBadRequest)
		return
	}
	if st.SnmpEnabled && strings.TrimSpace(st.SnmpHost) == "" {
		http.Error(w, "snmpHost is required when SNMP is enabled", http.StatusBadRequest)
		return
	}
	if err := s.e.PutSettings(st); err != nil {
		// A rejected lockdown (nothing here can enforce it) is a bad request,
		// not a server fault — surface it so the UI can say why.
		if errors.Is(err, engine.ErrInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.e.Settings())
}

func (s *Server) handleDevicePatch(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var p engine.DevicePatch
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	d, err := s.e.UpdateDevice(id, p)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, engine.ErrInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.e.ForgetDevice(id); err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, engine.ErrInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDevicePing(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	res, err := s.e.PingDevice(id)
	if err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// diagErr writes the standard not-found/invalid/internal error mapping used
// by the troubleshoot endpoints.
func diagErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, engine.ErrNotFound):
		http.Error(w, "device not found", http.StatusNotFound)
	case errors.Is(err, engine.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleDeviceTraceroute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	res, err := s.e.TracerouteDevice(id)
	if err != nil {
		diagErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeviceDNSLookup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	res, err := s.e.DNSLookup(id)
	if err != nil {
		diagErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeviceRenewDHCP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	res, err := s.e.RenewDHCP(id)
	if err != nil {
		diagErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeviceRestartRadio(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	res, err := s.e.RestartRadio(id)
	if err != nil {
		diagErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDeviceScan runs a port scan: body may carry {"ports":[...]} for a
// targeted sweep; empty → curated top-ports. Blocking on purpose — the
// scan itself is bounded (≤2000 ports, sub-second timeouts).
func (s *Server) handleDeviceScan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Ports []int `json:"ports"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
	}
	res, err := s.e.ScanDevice(id, body.Ports)
	if err != nil {
		diagErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDeviceScanLast returns the device's most recent stored scan.
func (s *Server) handleDeviceScanLast(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	res, found, err := s.e.LastScan(id)
	if err != nil {
		diagErr(w, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{"scan": nil})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.e.AckAlert(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleClearAlerts(w http.ResponseWriter, r *http.Request) {
	if err := s.e.ClearAlerts(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeviceIntel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.e.IntelFor(id, limit)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"intel": items})
}

func (s *Server) handleSpoofList(w http.ResponseWriter, r *http.Request) {
	rules, err := s.e.SpoofRules()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleSpoofAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	rule, err := s.e.PutSpoofRule(body.Domain, body.IP)
	if err != nil {
		if errors.Is(err, engine.ErrInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleSpoofDel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.e.DelSpoofRule(id); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// This stream is long-lived: clear the server's global WriteTimeout for
	// this connection only (the SSE handler is exempt from the 30s cap in
	// main.go, which still bounds every other handler).
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	ch := s.e.Hub().Subscribe()
	defer s.e.Hub().Unsubscribe(ch)

	// hello frame with the full current snapshot
	hello, err := json.Marshal(s.e.Snapshot())
	if err == nil {
		fmt.Fprintf(w, "event: hello\ndata: %s\n\n", hello)
		flusher.Flush()
	}

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case b, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "event: tick\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}
