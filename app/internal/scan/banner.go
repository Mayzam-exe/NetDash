package scan

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// grabBanners asks up to maxBannerPort open ports what they are, in
// parallel. Returns port → banner (only for ports that answered).
func grabBanners(ip string, open []int) map[int]string {
	if len(open) > maxBannerPort {
		open = open[:maxBannerPort]
	}
	out := make(map[int]string, len(open))
	var mu sync.Mutex
	sem := make(chan struct{}, bannerWorkers)
	var wg sync.WaitGroup
	for _, p := range open {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if b := grabBanner(ip, p); b != "" {
				mu.Lock()
				out[p] = b
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return out
}

func grabBanner(ip string, port int) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, bannerTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bannerTimeout))

	// request-first protocols
	switch {
	case isHTTPPort(port):
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: NetDash\r\nConnection: close\r\n\r\n", ip)
	case port == 6379: // redis
		_, _ = conn.Write([]byte("PING\r\n"))
	case port == 554: // rtsp
		fmt.Fprintf(conn, "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip)
	}

	// read whatever comes back (server-first banner or our answer)
	data := readSome(conn, isHTTPPort(port))
	if len(data) > 0 {
		if isHTTPPort(port) {
			return httpInfo(data)
		}
		return sanitize(data)
	}

	// silence: maybe it's a TLS service waiting for a ClientHello
	if s := tlsInfo(conn, ip); s != "" {
		return s
	}
	return ""
}

// readSome reads up to 4KB or until it has a plausible payload: for HTTP
// we stop at header end (+ a little body for <title>), otherwise first line.
func readSome(conn net.Conn, httpMode bool) []byte {
	var data []byte
	buf := make([]byte, 1024)
	for len(data) < 4096 {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if httpMode {
				if i := strings.Index(string(data), "\r\n\r\n"); i >= 0 {
					// keep reading a little for a <title>
					if len(data) >= 1024 {
						return data
					}
					_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
					continue
				}
			} else {
				return data // first response is enough
			}
		}
		if err != nil {
			break
		}
	}
	return data
}

// httpInfo summarizes an HTTP response: status, Server header, page title.
func httpInfo(data []byte) string {
	s := string(data)
	head, _, _ := strings.Cut(s, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "HTTP/") {
		return sanitize([]byte(s))
	}
	out := strings.TrimSpace(lines[0])
	var title string
	for _, l := range lines[1:] {
		if v, ok := cutCI(l, "Server:"); ok {
			out += " · server=" + strings.TrimSpace(v)
		}
	}
	body := s[len(head):]
	if i := strings.Index(strings.ToLower(body), "<title>"); i >= 0 {
		rest := body[i+7:]
		if j := strings.Index(strings.ToLower(rest), "</title>"); j > 0 {
			title = strings.TrimSpace(rest[:j])
		}
	}
	if title != "" {
		out += " · title=" + title
	}
	return out
}

// tlsInfo handshakes over an existing (untouched) connection and reports
// TLS version, certificate CN and ALPN.
func tlsInfo(conn net.Conn, ip string) string {
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // we're fingerprinting, not authenticating
		ServerName:         ip,
	})
	_ = tc.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	if err := tc.Handshake(); err != nil {
		return ""
	}
	st := tc.ConnectionState()
	var parts []string
	parts = append(parts, tlsVersionName(st.Version))
	if len(st.PeerCertificates) > 0 {
		if cn := certCN(st.PeerCertificates[0]); cn != "" {
			parts = append(parts, "CN="+cn)
		}
	}
	if st.NegotiatedProtocol != "" {
		parts = append(parts, "ALPN="+st.NegotiatedProtocol)
	}
	return strings.Join(parts, " ")
}

func certCN(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return ""
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("TLS(0x%04x)", v)
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 81, 3000, 5000, 5001, 8000, 8008, 8010, 8080, 8081, 8082,
		8086, 8088, 8090, 8888, 9000, 9090, 9091, 5601, 3128:
		return true
	}
	return false
}

// sanitize squeezes a protocol blob into one printable line.
func sanitize(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		if r == '\n' || r == '\r' {
			if sb.Len() > 0 {
				break
			}
			continue
		}
		if r < 32 || r == 127 {
			continue // binary junk (e.g. length prefixes)
		}
		sb.WriteRune(r)
		if sb.Len() >= 160 {
			break
		}
	}
	return strings.TrimSpace(sb.String())
}

func cutCI(line, prefix string) (string, bool) {
	if len(line) >= len(prefix) && strings.EqualFold(line[:len(prefix)], prefix) {
		return line[len(prefix):], true
	}
	return "", false
}
