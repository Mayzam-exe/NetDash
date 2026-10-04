package discover

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type Neighbor struct {
	IP    string
	MAC   string
	Valid bool // complete/confirmed entry
}

// Neighbors returns the current ARP/neighbor table of the host.
func Neighbors() ([]Neighbor, error) {
	if runtime.GOOS == "windows" {
		return neighborsWindows()
	}
	return neighborsLinux()
}

func neighborsLinux() ([]Neighbor, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Neighbor
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		n := Neighbor{IP: fields[0], MAC: fields[3], Valid: fields[2] == "0x2"}
		if n.MAC == "00:00:00:00:00:00" {
			n.Valid = false
		}
		out = append(out, n)
	}
	return out, sc.Err()
}

func neighborsWindows() ([]Neighbor, error) {
	cmd := exec.Command("arp", "-a")
	b, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var out []Neighbor
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		mac := ""
		for _, f := range fields[1:] {
			if isMAC(f) {
				mac = f
				break
			}
		}
		if ip == "" || mac == "" {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: normalizeMAC(mac), Valid: true})
	}
	return out, nil
}

func isMAC(s string) bool {
	if len(s) < 17 {
		return false
	}
	for i, c := range s {
		if (i+1)%3 == 0 {
			if c != '-' && c != ':' {
				return false
			}
		} else if !isHex(byte(c)) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// normalizeMAC lowercases and uses colon separators.
func normalizeMAC(m string) string {
	m = strings.ToLower(strings.ReplaceAll(m, "-", ":"))
	return m
}
