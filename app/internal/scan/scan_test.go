package scan

import (
	"fmt"
	"net"
	"testing"
)

func TestServiceOf(t *testing.T) {
	for port, want := range map[int]string{
		22: "ssh", 443: "https", 3306: "mysql", 6379: "redis", 27017: "mongodb",
	} {
		if got := serviceOf(port); got != want {
			t.Errorf("serviceOf(%d) = %q, want %q", port, got, want)
		}
	}
	if got := serviceOf(4242); got != "" {
		t.Errorf("serviceOf(4242) = %q, want empty", got)
	}
}

func TestTopPortsValid(t *testing.T) {
	seen := map[int]bool{}
	for _, p := range TopPorts() {
		if p < 1 || p > 65535 {
			t.Fatalf("bad port %d", p)
		}
		if seen[p] {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = true
	}
	if len(seen) < 80 {
		t.Errorf("only %d curated ports, expected a real sweep", len(seen))
	}
}

func TestScanLoopbackFindsOpenAndClosed(t *testing.T) {
	// open listener that answers with a banner
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("HELLO-FROM-TEST\r\n"))
				_, _ = c.Read(make([]byte, 64))
			}(c)
		}
	}()

	// grab a port that is definitely closed (open then release it)
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	res := Scan("127.0.0.1", []int{openPort, closedPort, 1})
	if res.Open != 1 {
		t.Fatalf("Open = %d, want 1 (ports %+v, method %s)", res.Open, res.Ports, res.Method)
	}
	if res.Ports[0].Port != openPort {
		t.Fatalf("open port = %d, want %d", res.Ports[0].Port, openPort)
	}
	if res.Ports[0].Banner == "" {
		t.Errorf("expected banner from test listener")
	}
	if res.Probed != 3 {
		t.Errorf("Probed = %d, want 3", res.Probed)
	}
	if res.Method != "syn" && res.Method != "connect" {
		t.Errorf("Method = %q", res.Method)
	}
	t.Logf("method=%s open=%d banner=%q", res.Method, res.Open, res.Ports[0].Banner)
}

func TestScanRejectsNothingOnEmpty(t *testing.T) {
	res := Scan("127.0.0.1", nil)
	if res.Open != 0 || len(res.Ports) != 0 || res.Probed != 0 {
		t.Errorf("unexpected %+v", res)
	}
}

func TestHTTPInfo(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n\r\n<html><title>Router Admin</title></html>"
	got := httpInfo([]byte(raw))
	for _, want := range []string{"HTTP/1.1 200 OK", "server=nginx/1.25.3", "title=Router Admin"} {
		if !contains(got, want) {
			t.Errorf("httpInfo = %q, missing %q", got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize([]byte{0x0e, 0x00, '5', '.', '7', '.', '4', '0', '-', 'l', 'o', 'g', 0, '\n'}); got != "5.7.40-log" {
		t.Errorf("sanitize = %q", got)
	}
	if got := sanitize([]byte("SSH-2.0-OpenSSH_9.6")); got != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("sanitize = %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

var _ = fmt.Sprintf
