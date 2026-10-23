package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"netdash/internal/model"

	_ "modernc.org/sqlite"
)

type Store struct {
	dir string
	db  *sql.DB
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "netdash.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	schema := `
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL UNIQUE,
  mac TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  vendor TEXT NOT NULL DEFAULT '',
  conn TEXT NOT NULL DEFAULT 'unknown',
  blocked INTEGER NOT NULL DEFAULT 0,
  reserved INTEGER NOT NULL DEFAULT 0,
  trusted INTEGER NOT NULL DEFAULT 0,
  priority TEXT NOT NULL DEFAULT 'normal',
  schedule TEXT NOT NULL DEFAULT '',
  speed_down INTEGER NOT NULL DEFAULT 0,
  speed_up INTEGER NOT NULL DEFAULT 0,
  watched INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sev TEXT NOT NULL,
  msg TEXT NOT NULL,
  dev_id INTEGER,
  ts INTEGER NOT NULL,
  read INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intel(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dev_id INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS intel_dev_ts ON intel(dev_id, ts);
CREATE TABLE IF NOT EXISTS spoof_rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL UNIQUE,
  ip TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans(
  dev_id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  result TEXT NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, dir: dataDir}, nil
}

// Dir returns the data directory the store was opened on.
func (s *Store) Dir() string { return s.dir }

// migrate applies additive column migrations for databases created before
// the column existed.
func migrate(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(devices)`)
	if err != nil {
		return err
	}
	hasKind := false
	hasSpeedDown := false
	hasSpeedUp := false
	hasWatched := false
	hasTrusted := false
	for rows.Next() {
		var cid, notnull int
		var name, typ string
		var dflt, pk any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		switch name {
		case "kind":
			hasKind = true
		case "speed_down":
			hasSpeedDown = true
		case "speed_up":
			hasSpeedUp = true
		case "watched":
			hasWatched = true
		case "trusted":
			hasTrusted = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasKind {
		if _, err := db.Exec(`ALTER TABLE devices ADD COLUMN kind TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !hasSpeedDown {
		if _, err := db.Exec(`ALTER TABLE devices ADD COLUMN speed_down INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !hasSpeedUp {
		if _, err := db.Exec(`ALTER TABLE devices ADD COLUMN speed_up INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !hasWatched {
		if _, err := db.Exec(`ALTER TABLE devices ADD COLUMN watched INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !hasTrusted {
		if _, err := db.Exec(`ALTER TABLE devices ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	// One-time repair: devices created while the schema defaulted
	// schedule to '07:00-23:00' would be auto-blocked outside that window
	// (the 23:00 mass-poisoning bug). Empty = always allowed.
	var seen string
	err = db.QueryRow(`SELECT value FROM meta WHERE key='schedule_default_v1'`).Scan(&seen)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := db.Exec(`UPDATE devices SET schedule='' WHERE schedule='07:00-23:00'`); err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('schedule_default_v1', '1')`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func scanDevice(row interface{ Scan(...any) error }) (model.Device, error) {
	var d model.Device
	var blocked, reserved, trusted, watched int
	var first, last int64
	err := row.Scan(&d.ID, &d.IP, &d.MAC, &d.Name, &d.Vendor, &d.Kind, &d.Conn, &blocked, &reserved,
		&trusted, &d.Priority, &d.Schedule, &d.SpeedDown, &d.SpeedUp, &watched, &first, &last)
	if err != nil {
		return d, err
	}
	d.Blocked = blocked != 0
	d.Reserved = reserved != 0
	d.Trusted = trusted != 0
	d.Watched = watched != 0
	if first > 0 {
		t := time.UnixMilli(first).UTC()
		d.FirstSeen = &t
	}
	if last > 0 {
		t := time.UnixMilli(last).UTC()
		d.LastSeen = &t
	}
	return d, nil
}

const devCols = `id, ip, mac, name, vendor, kind, conn, blocked, reserved, trusted, priority, schedule, speed_down, speed_up, watched, first_seen, last_seen`

func (s *Store) ListDevices() ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT ` + devCols + ` FROM devices ORDER BY name, ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpsertDevice inserts or updates the persistent identity row. Returns the row and whether it is new.
func (s *Store) UpsertDevice(ip, mac, vendor string, now int64) (model.Device, bool, error) {
	existing, err := s.db.Query(`SELECT `+devCols+` FROM devices WHERE ip = ?`, ip)
	if err != nil {
		return model.Device{}, false, err
	}
	var d model.Device
	found := false
	if existing.Next() {
		d, err = scanDevice(existing)
		found = err == nil
	}
	existing.Close()
	if found {
		newMac := mac
		if newMac == "" {
			newMac = d.MAC
		}
		newVendor := vendor
		if newVendor == "" {
			newVendor = d.Vendor
		}
		_, err = s.db.Exec(`UPDATE devices SET mac = ?, vendor = ?, last_seen = ? WHERE id = ?`,
			newMac, newVendor, now, d.ID)
		if err != nil {
			return model.Device{}, false, err
		}
		d.MAC, d.Vendor = newMac, newVendor
		t := time.UnixMilli(now).UTC()
		d.LastSeen = &t
		return d, false, nil
	}
	name := defaultName(ip)
	res, err := s.db.Exec(`INSERT INTO devices(ip, mac, vendor, name, conn, schedule, first_seen, last_seen)
		VALUES(?, ?, ?, ?, 'unknown', '', ?, ?)`, ip, mac, vendor, name, now, now)
	if err != nil {
		return model.Device{}, false, err
	}
	id, _ := res.LastInsertId()
	t := time.UnixMilli(now).UTC()
	return model.Device{
		ID: id, IP: ip, MAC: mac, Name: name, Vendor: vendor, Conn: "unknown",
		Priority: "normal", Schedule: "",
		FirstSeen: &t, LastSeen: &t,
	}, true, nil
}

func defaultName(ip string) string {
	return "Device " + ip
}

// SaveDevice persists the mutable/identity fields of a device (all except live metrics).
func (s *Store) SaveDevice(d model.Device) error {
	var first, last int64
	if d.FirstSeen != nil {
		first = d.FirstSeen.UnixMilli()
	}
	if d.LastSeen != nil {
		last = d.LastSeen.UnixMilli()
	}
	_, err := s.db.Exec(`UPDATE devices SET mac=?, name=?, vendor=?, kind=?, conn=?, blocked=?, reserved=?, trusted=?,
		priority=?, schedule=?, speed_down=?, speed_up=?, watched=?, first_seen=?, last_seen=? WHERE id=?`,
		d.MAC, d.Name, d.Vendor, d.Kind, d.Conn, boolInt(d.Blocked), boolInt(d.Reserved), boolInt(d.Trusted),
		d.Priority, d.Schedule, d.SpeedDown, d.SpeedUp, boolInt(d.Watched), first, last, d.ID)
	return err
}

const intelRetention = 7 * 24 * 3600 * 1000 // 7 days in unix ms

// SaveIntel appends one hostname observation and prunes expired rows.
func (s *Store) SaveIntel(devID int64, kind, value string, ts int64) error {
	if value == "" || kind == "" {
		return nil
	}
	if _, err := s.db.Exec(`INSERT INTO intel(dev_id, ts, kind, value) VALUES(?,?,?,?)`,
		devID, ts, kind, value); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM intel WHERE ts < ?`, ts-intelRetention)
	return err
}

// ListIntel returns a device's newest hostname observations.
func (s *Store) ListIntel(devID int64, limit int) ([]model.Intel, error) {
	if limit <= 0 || limit > 500 {
		limit = 120
	}
	rows, err := s.db.Query(`SELECT id, dev_id, ts, kind, value FROM intel
		WHERE dev_id = ? ORDER BY ts DESC, id DESC LIMIT ?`, devID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Intel
	for rows.Next() {
		var it model.Intel
		if err := rows.Scan(&it.ID, &it.DevID, &it.TS, &it.Kind, &it.Value); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// SaveScan replaces a device's last port-scan result (one row per device).
func (s *Store) SaveScan(devID int64, ts int64, resultJSON string) error {
	_, err := s.db.Exec(`INSERT INTO scans(dev_id, ts, result) VALUES(?,?,?)
		ON CONFLICT(dev_id) DO UPDATE SET ts=excluded.ts, result=excluded.result`,
		devID, ts, resultJSON)
	return err
}

// GetScan returns a device's last port-scan result JSON and when it ran.
func (s *Store) GetScan(devID int64) (string, int64, bool, error) {
	var res string
	var ts int64
	err := s.db.QueryRow(`SELECT result, ts FROM scans WHERE dev_id = ?`, devID).Scan(&res, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return res, ts, true, nil
}

// ListSpoofRules returns every DNS spoof rule.
func (s *Store) ListSpoofRules() ([]model.SpoofRule, error) {
	rows, err := s.db.Query(`SELECT id, domain, ip FROM spoof_rules ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SpoofRule
	for rows.Next() {
		var r model.SpoofRule
		if err := rows.Scan(&r.ID, &r.Domain, &r.IP); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddSpoofRule inserts or updates a suffix -> ip rule.
func (s *Store) AddSpoofRule(domain, ip string) (model.SpoofRule, error) {
	_, err := s.db.Exec(`INSERT INTO spoof_rules(domain, ip) VALUES(?,?)
		ON CONFLICT(domain) DO UPDATE SET ip=excluded.ip`, domain, ip)
	if err != nil {
		return model.SpoofRule{}, err
	}
	var r model.SpoofRule
	err = s.db.QueryRow(`SELECT id, domain, ip FROM spoof_rules WHERE domain=?`, domain).
		Scan(&r.ID, &r.Domain, &r.IP)
	return r, err
}

// DeleteSpoofRule removes one rule by id.
func (s *Store) DeleteSpoofRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM spoof_rules WHERE id=?`, id)
	return err
}

func (s *Store) TouchSeen(id int64, now int64) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen=? WHERE id=?`, now, id)
	return err
}

// DeleteDevice forgets a device permanently (alerts referencing it are kept
// as history; they do not join on the device row).
func (s *Store) DeleteDevice(id int64) error {
	_, err := s.db.Exec(`DELETE FROM devices WHERE id=?`, id)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const alertRetention = 30 * 24 * 3600 * 1000 // 30 days in unix ms

func (s *Store) AddAlert(sev, msg string, devID *int64, ts int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO alerts(sev, msg, dev_id, ts, read) VALUES(?,?,?,? ,0)`,
		sev, msg, devID, ts)
	if err != nil {
		return 0, err
	}
	// Bound the table (and its WAL) with a retention window, mirroring the
	// intel table. Previously alerts were never deleted.
	_, _ = s.db.Exec(`DELETE FROM alerts WHERE ts < ?`, ts-alertRetention)
	return res.LastInsertId()
}

func (s *Store) ListAlerts(limit int) ([]model.Alert, error) {
	rows, err := s.db.Query(`SELECT id, sev, msg, dev_id, ts, read FROM alerts ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		var devID sql.NullInt64
		var read int
		if err := rows.Scan(&a.ID, &a.Sev, &a.Msg, &devID, &a.TS, &read); err != nil {
			return nil, err
		}
		if devID.Valid {
			v := devID.Int64
			a.DevID = &v
		}
		a.Read = read != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AckAlert(id int64) error {
	_, err := s.db.Exec(`UPDATE alerts SET read=1 WHERE id=?`, id)
	return err
}

// ClearAlerts removes every row — the whole log, not just the unread ones.
func (s *Store) ClearAlerts() error {
	_, err := s.db.Exec(`DELETE FROM alerts`)
	return err
}

func (s *Store) GetSettings() (model.Settings, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key='settings'`).Scan(&raw)
	if err == sql.ErrNoRows {
		return model.DefaultSettings(), nil
	}
	if err != nil {
		return model.Settings{}, err
	}
	var st model.Settings
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return model.DefaultSettings(), nil
	}
	return st, nil
}

func (s *Store) PutSettings(st model.Settings) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO meta(key, value) VALUES('settings', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(b))
	return err
}

func (s *Store) MetaGet(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *Store) MetaSet(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
