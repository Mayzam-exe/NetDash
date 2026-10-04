package engine

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"netdash/internal/scan"
)

// maxScanPorts bounds one sweep so a request can't monopolize the raw
// socket or the API for long.
const maxScanPorts = 2000

// scanMu serializes scans: one sweep at a time (they share raw source
// ports and the CAP_NET_RAW socket path).
var scanMu sync.Mutex

// ScanDevice probes the device's ports (empty list → curated top-ports
// sweep), grabs banners and persists the result as the device's last scan.
func (e *Engine) ScanDevice(id int64, ports []int) (scan.Result, error) {
	e.mu.RLock()
	d, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return scan.Result{}, ErrNotFound
	}
	if d.IP == "" {
		return scan.Result{}, fmt.Errorf("%w: device has no IP", ErrInvalid)
	}
	if len(ports) == 0 {
		ports = scan.TopPorts()
	}
	if len(ports) > maxScanPorts {
		return scan.Result{}, fmt.Errorf("%w: at most %d ports per scan", ErrInvalid, maxScanPorts)
	}
	seen := make(map[int]bool, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return scan.Result{}, fmt.Errorf("%w: port %d out of range", ErrInvalid, p)
		}
		if seen[p] {
			return scan.Result{}, fmt.Errorf("%w: duplicate port %d", ErrInvalid, p)
		}
		seen[p] = true
	}

	scanMu.Lock()
	res := scan.Scan(d.IP, ports)
	scanMu.Unlock()

	res.ScannedAt = time.Now().UnixMilli()
	if b, err := json.Marshal(res); err == nil {
		_ = e.st.SaveScan(id, res.ScannedAt, string(b))
	}
	return res, nil
}

// LastScan returns a device's persisted most recent scan, if any.
func (e *Engine) LastScan(id int64) (scan.Result, bool, error) {
	e.mu.RLock()
	_, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return scan.Result{}, false, ErrNotFound
	}
	raw, _, found, err := e.st.GetScan(id)
	if err != nil || !found {
		return scan.Result{}, false, err
	}
	var res scan.Result
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return scan.Result{}, false, err
	}
	return res, true, nil
}
