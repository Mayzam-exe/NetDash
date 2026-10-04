package ident

import "strings"

// Kinds is the full set of device kinds the UI has icons for.
var Kinds = []string{
	"phone", "laptop", "desktop", "tablet", "tv", "camera",
	"speaker", "thermostat", "printer", "hub", "console", "router",
}

// ValidKind reports whether k is an acceptable kind value ("" means auto).
func ValidKind(k string) bool {
	if k == "" {
		return true
	}
	for _, v := range Kinds {
		if k == v {
			return true
		}
	}
	return false
}

// Infer guesses a device kind from hostname, OUI vendor and network position.
// It returns "" when nothing matches confidently — callers treat "" as unknown
// rather than guessing. Priority: gateway position > hostname > vendor.
func Infer(name, vendor, mac, ip, gatewayIP string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	v := strings.ToLower(strings.TrimSpace(vendor))

	// The gateway is a router regardless of what its OUI says.
	if ip != "" && gatewayIP != "" && ip == gatewayIP {
		return "router"
	}
	if n == "_gateway" || n == "gateway" {
		return "router"
	}

	if k := inferHostname(n); k != "" {
		return k
	}
	return inferVendor(v, macLocallyAdministered(mac))
}

// splitWords splits s on any non-alphanumeric run, so hyphenated DHCP names
// like "living-room-tv" or "joes-iphone" tokenize like "living room tv".
func splitWords(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	})
}

// hasToken reports whether any alphanumeric word in s equals tok.
func hasToken(s, tok string) bool {
	for _, w := range splitWords(s) {
		if w == tok {
			return true
		}
	}
	return false
}

// hasPrefixAtWord reports whether pref occurs at the start of a word (word
// boundary = string start or any non-alphanumeric byte). Unlike token
// matching, pref itself may contain hyphens, so model-number hostnames like
// "sm-g991b" or "gt-i9300" match while "dsm-admin" (pref mid-word) does not.
func hasPrefixAtWord(s, pref string) bool {
	for i := 0; i+len(pref) <= len(s); i++ {
		if !strings.HasPrefix(s[i:], pref) {
			continue
		}
		if i == 0 {
			return true
		}
		if c := s[i-1]; !(('a' <= c && c <= 'z') || ('0' <= c && c <= '9')) {
			return true
		}
	}
	return false
}

// hasTokenPair reports whether s contains first immediately followed by one of
// the seconds ("mac pro", "mac-mini"), across any separator.
func hasTokenPair(s, first string, seconds ...string) bool {
	w := splitWords(s)
	for i := 0; i+1 < len(w); i++ {
		if w[i] != first {
			continue
		}
		for _, t := range seconds {
			if w[i+1] == t {
				return true
			}
		}
	}
	return false
}

// inferHostname matches DHCP/DNS names. First match wins; patterns are
// deliberately anchored on distinctive tokens to limit false positives.
func inferHostname(n string) string {
	switch {
	case containsAny(n, "iphone", "ipod touch"):
		return "phone"
	case containsAny(n, "ipad", "tablet"):
		return "tablet"
	case containsAny(n, "macbook", "powerbook"):
		return "laptop"
	case containsAny(n, "imac") || hasTokenPair(n, "mac", "pro", "mini"):
		return "desktop"
	case containsAny(n, "apple tv", "appletv"), hasToken(n, "tv"), hasToken(n, "television"):
		return "tv"
	case hasToken(n, "mac") || hasToken(n, "thinkpad") || containsAny(n, "latitude", "inspiron", "laptop", "notebook", "surface"):
		return "laptop"
	case containsAny(n, "desktop-", "workstation") || hasToken(n, "pc"):
		return "desktop"
	case containsAny(n, "galaxy", "redmi", "pixel", "oneplus", "one plus", "android") ||
		hasPrefixAtWord(n, "sm-") || hasPrefixAtWord(n, "gt-i") ||
		hasPrefixAtWord(n, "rmx") || hasPrefixAtWord(n, "cph") || hasPrefixAtWord(n, "poco"):
		return "phone"
	case containsAny(n, "esp32", "esp8266", "esp-", "tuya", "smartlife", "sonoff", "shelly", "wled"):
		return "hub"
	case containsAny(n, "roku", "chromecast", "firetv", "fire tv", "bravia", "smarttv"):
		return "tv"
	case containsAny(n, "printer", "laserjet", "deskjet", "photosmart"):
		return "printer"
	case containsAny(n, "ps5", "ps4", "ps3", "xbox", "nintendo", "switch-"):
		return "console"
	case containsAny(n, "sonos", "echo-", "alexa", "homepod", "speaker"):
		return "speaker"
	case containsAny(n, "thermostat", "ecobee", "nest-"):
		return "thermostat"
	case containsAny(n, "camera", "doorbell", "door cam", "nvr", "wyze", "reolink"):
		return "camera"
	}
	return ""
}

// inferVendor maps IEEE OUI vendor names to a kind. Ambiguous vendors fall
// through to "" instead of guessing.
func inferVendor(v string, locallyAdministered bool) string {
	switch {
	case v == "":
		return ""
	case strings.Contains(v, "apple"):
		// iPhones randomize their Wi-Fi MAC (locally administered bit set);
		// Macs normally carry a burned-in address.
		if locallyAdministered {
			return "phone"
		}
		return "laptop"
	case containsAny(v, "xiaomi", "huawei", "oppo", "vivo", "oneplus",
		"realme", "google", "motorola", "honor", "infinix", "tecno"):
		return "phone"
	// Samsung deliberately omitted: it builds phones, TVs, monitors and
	// appliances, so a bare "Samsung" vendor proves nothing — stay unknown
	// and let the hostname (SM-*, "…TV") or a manual override decide.
	case containsAny(v, "raspberry"):
		return "desktop"
	case containsAny(v, "dell", "lenovo", "toshiba", "acer ", "asus"):
		return "laptop"
	case containsAny(v, "espressif", "tuya", "itead", "sonoff", "zboss", "silicon laboratories"):
		return "hub"
	case containsAny(v, "hewlett-packard", "hp inc", "epson", "canon", "brother", "ricoh", "xerox"):
		return "printer"
	case containsAny(v, "hikvision", "dahua", "axis communications"):
		return "camera"
	case containsAny(v, "sonos"):
		return "speaker"
	case containsAny(v, "nintendo"):
		return "console"
	case containsAny(v, "philips"):
		return "hub"
	case containsAny(v, "amazon"):
		return "speaker"
	case containsAny(v, "roku"):
		return "tv"
	}
	return ""
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// macLocallyAdministered reports whether s looks like a MAC (aa:bb:cc… or
// aa-bb-cc…) whose first octet has the locally-administered bit set.
func macLocallyAdministered(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 8 {
		return false
	}
	sep := s[2]
	if sep != ':' && sep != '-' {
		return false
	}
	hi, ok1 := hexVal(s[0])
	lo, ok2 := hexVal(s[1])
	if !ok1 || !ok2 {
		return false
	}
	return (hi<<4|lo)&0x02 != 0
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
