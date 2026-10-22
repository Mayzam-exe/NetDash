package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netdash/internal/engine"
	"netdash/internal/store"
)

func newTestServer(t *testing.T, token string) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng, err := engine.New(st, engine.NewHub())
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return New(eng, token)
}

func TestWithAuth(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No token configured: everything passes.
	h := withAuth(ok, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("no-token: code=%d want 200", rec.Code)
	}

	h = withAuth(ok, "s3cret")

	// Missing token on /api/* → 401.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: code=%d want 401", rec.Code)
	}

	// Wrong token → 401.
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer nope")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: code=%d want 401", rec.Code)
	}

	// Correct bearer → 200.
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer: code=%d want 200", rec.Code)
	}

	// Correct query token (used by EventSource) → 200.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/stream?token=s3cret", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("query token: code=%d want 200", rec.Code)
	}

	// Static assets are never gated.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/index.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("static: code=%d want 200", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	for _, k := range []string{
		"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy",
	} {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
}

func TestPutSettingsValidatesIPs(t *testing.T) {
	s := newTestServer(t, "")

	bad := `{"gatewayIp":"not-an-ip","wanIp":"1.1.1.1"}`
	rec := httptest.NewRecorder()
	s.handlePutSettings(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(bad)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad gateway ip: code=%d want 400", rec.Code)
	}

	badWan := `{"gatewayIp":"192.168.1.1","wanIp":"999.1.1.1"}`
	rec = httptest.NewRecorder()
	s.handlePutSettings(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(badWan)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad wan ip: code=%d want 400", rec.Code)
	}

	good := `{"gatewayIp":"192.168.1.1","wanIp":"1.1.1.1"}`
	rec = httptest.NewRecorder()
	s.handlePutSettings(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(good)))
	if rec.Code != http.StatusOK {
		t.Fatalf("good settings: code=%d want 200 (%s)", rec.Code, rec.Body.String())
	}
}

// TestPutSettingsLockdownRequiresEnforcement: the panic switch must be
// refused when the host cannot apply it. Silently accepting it would show a
// protected network that is not protected.
func TestPutSettingsLockdownRequiresEnforcement(t *testing.T) {
	s := newTestServer(t, "")
	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handlePutSettings(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body)))
		return rec
	}

	// This fixture has no firewall capability and no ARP bridge.
	rec := put(`{"gatewayIp":"192.168.1.1","wanIp":"1.1.1.1","lockdown":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unenforceable lockdown: code=%d want 400 (%s)", rec.Code, rec.Body.String())
	}

	rec = put(`{"gatewayIp":"192.168.1.1","wanIp":"1.1.1.1","lockdown":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("release: code=%d want 200 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"lockdown":false`) {
		t.Fatalf("response does not echo lockdown state: %s", rec.Body.String())
	}
}
