package firewall

import "testing"

func TestParseCounters(t *testing.T) {
	fixture := []byte(`{
	  "nftables": [
	    {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
	    {"table": {"family": "inet", "name": "netdash", "handle": 42}},
	    {"chain": {"family": "inet", "table": "netdash", "name": "forward",
	              "handle": 1, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
	    {"rule": {"family": "inet", "table": "netdash", "chain": "forward", "handle": 2,
	              "expr": [
	                {"match": {"op": "==",
	                           "left": {"payload": {"protocol": "ip", "field": "saddr"}},
	                           "right": {"prefix": {"addr": {"ip": "192.168.1.50"}, "len": 32}}}},
	                {"counter": {"packets": 10, "bytes": 12345}},
	                {"comment": "nd:up:192.168.1.50"}
	              ]}},
	    {"rule": {"family": "inet", "table": "netdash", "chain": "forward", "handle": 4,
	              "expr": [
	                {"match": {"op": "==",
	                           "left": {"payload": {"protocol": "ip", "field": "daddr"}},
	                           "right": {"prefix": {"addr": {"ip": "192.168.1.50"}, "len": 32}}}},
	                {"counter": {"packets": 5, "bytes": 999}},
	                {"comment": "nd:down:192.168.1.50"}
	              ]}},
	    {"rule": {"family": "inet", "table": "netdash", "chain": "forward", "handle": 6,
	              "expr": [
	                {"match": {"op": "==",
	                           "left": {"payload": {"protocol": "ip", "field": "saddr"}},
	                           "right": {"prefix": {"addr": {"ip": "192.168.1.60"}, "len": 32}}}},
	                {"verdict": {"drop": null}}
	              ]}}
	  ]
	}`)

	got, err := parseCounters(fixture)
	if err != nil {
		t.Fatalf("parseCounters: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d counters, want 2: %v", len(got), got)
	}
	if got["up:192.168.1.50"] != 12345 {
		t.Errorf("up:192.168.1.50 = %d, want 12345", got["up:192.168.1.50"])
	}
	if got["down:192.168.1.50"] != 999 {
		t.Errorf("down:192.168.1.50 = %d, want 999", got["down:192.168.1.50"])
	}

	// garbage input errors out
	if _, err := parseCounters([]byte("not json")); err == nil {
		t.Error("parseCounters(non-json) = nil error, want error")
	}
}
