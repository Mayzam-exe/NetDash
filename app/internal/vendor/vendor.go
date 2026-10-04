package vendor

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.csv
var ouiCSV string

var (
	once  sync.Once
	table map[string]string
)

func load() {
	once.Do(func() {
		table = make(map[string]string, 40960)
		for _, line := range strings.Split(ouiCSV, "\n") {
			if len(line) < 9 {
				continue
			}
			var bin [3]byte
			ok := true
			for i := 0; i < 6; i++ {
				c := line[i]
				var v byte
				switch {
				case c >= '0' && c <= '9':
					v = c - '0'
				case c >= 'a' && c <= 'f':
					v = c - 'a' + 10
				default:
					ok = false
				}
				if !ok {
					break
				}
				if i%2 == 0 {
					bin[i/2] = v << 4
				} else {
					bin[i/2] |= v
				}
			}
			if !ok {
				continue
			}
			v := strings.TrimSpace(line[7:])
			if v != "" {
				table[string(bin[:])] = v
			}
		}
	})
}

// Lookup returns the IEEE vendor name for a MAC address (first 24 bits), or "".
func Lookup(mac string) string {
	var key [6]byte
	n := 0
	for i := 0; i < len(mac) && n < 6; i++ {
		c := mac[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			continue
		}
		if n%2 == 0 {
			key[n/2] = v << 4
		} else {
			key[n/2] |= v
		}
		n++
	}
	if n < 6 {
		return ""
	}
	load()
	return table[string(key[:3])]
}
