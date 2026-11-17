package platform

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	db       *sql.DB
	postgres bool
}
type bootstrap struct {
	Database string `json:"database"`
	DSN      string `json:"dsn"`
}

func ID() string { return uuid.NewString() }
func OpenStore(kind, dsn string) (*Store, error) {
	driver := "sqlite"
	if kind == "postgres" {
		driver = "pgx"
	} else if kind != "sqlite" {
		return nil, errors.New("数据库类型仅支持 sqlite 或 postgres")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, postgres: kind == "postgres"}
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if !s.postgres {
		if _, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
			db.Close()
			return nil, err
		}
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS platform_objects (kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(kind,id))")
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) q(q string) string {
	if !s.postgres {
		return q
	}
	for i := 1; strings.Contains(q, "?"); i++ {
		q = strings.Replace(q, "?", fmt.Sprintf("$%d", i), 1)
	}
	return q
}
func (s *Store) put(kind, id string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = s.db.Exec(s.q("INSERT INTO platform_objects(kind,id,payload,created_at) VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload"), kind, id, string(b), time.Now().UTC().Format(time.RFC3339Nano))
	return e
}
func (s *Store) get(kind, id string, v any) error {
	var b string
	e := s.db.QueryRow(s.q("SELECT payload FROM platform_objects WHERE kind=? AND id=?"), kind, id).Scan(&b)
	if e != nil {
		return e
	}
	return json.Unmarshal([]byte(b), v)
}
func (s *Store) all(kind string, v any) error {
	rows, e := s.db.Query(s.q("SELECT payload FROM platform_objects WHERE kind=? ORDER BY created_at DESC"), kind)
	if e != nil {
		return e
	}
	defer rows.Close()
	a := []json.RawMessage{}
	for rows.Next() {
		var b string
		if e = rows.Scan(&b); e != nil {
			return e
		}
		a = append(a, json.RawMessage(b))
	}
	if e = rows.Err(); e != nil {
		return e
	}
	b, e := json.Marshal(a)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (s *Store) Config() (Config, error) {
	c := DefaultConfig()
	c.AI.RetryCount = 5
	c.RetentionVersion = 0
	e := s.get("config", "main", &c)
	if e == nil && c.RetentionVersion < 1 {
		c.DeliveryRetentionDays = 7
		c.AI.RetentionDays = 7
		c.RetentionVersion = 1
		e = s.SaveConfig(c)
	}
	c.Branding.Title = "WatchVuln AI"
	c.Branding.Logo = "/logo.svg"
	return c, e
}
func (s *Store) SaveConfig(c Config) error { return s.put("config", "main", c) }
func (s *Store) Users() ([]User, error) {
	var raw []struct {
		User
		Hash string `json:"hash"`
	}
	e := s.all("user", &raw)
	a := []User{}
	for _, r := range raw {
		r.User.PasswordHash = r.Hash
		a = append(a, r.User)
	}
	return a, e
}
func (s *Store) SaveUser(u User) error {
	return s.put("user", u.ID, struct {
		User
		Hash string `json:"hash"`
	}{u, u.PasswordHash})
}
func (s *Store) User(id string) (User, error) {
	var r struct {
		User
		Hash string `json:"hash"`
	}
	e := s.get("user", id, &r)
	r.User.PasswordHash = r.Hash
	return r.User, e
}
func (s *Store) FindUser(provider, name string) (User, error) {
	a, e := s.Users()
	if e != nil {
		return User{}, e
	}
	for _, u := range a {
		if u.Provider == provider && u.Username == name {
			return u, nil
		}
	}
	return User{}, sql.ErrNoRows
}
func (s *Store) PutVulnerability(v Vulnerability) (bool, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return false, e
	}
	r, e := s.db.Exec(s.q("INSERT INTO platform_objects(kind,id,payload,created_at) VALUES('vulnerability',?,?,?) ON CONFLICT(kind,id) DO NOTHING"), v.ID, string(b), v.CreatedAt.UTC().Format(time.RFC3339Nano))
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	if e == nil && n == 0 {
		e = s.fillVulnerabilityGaps(v)
	}
	return n > 0, e
}
func (s *Store) Vulnerabilities() ([]Vulnerability, error) {
	a := []Vulnerability{}
	e := s.all("vulnerability", &a)
	return a, e
}
func (s *Store) PutReport(r Report) error   { return s.put("report", r.ID, r) }
func (s *Store) Reports() ([]Report, error) { a := []Report{}; e := s.all("report", &a); return a, e }
func (s *Store) Report(id string) (Report, error) {
	var r Report
	e := s.get("report", id, &r)
	return r, e
}
func (s *Store) PutDelivery(d Delivery) error { return s.put("delivery", d.ID, d) }
func (s *Store) Deliveries() ([]Delivery, error) {
	a := []Delivery{}
	e := s.all("delivery", &a)
	return a, e
}
func saveBootstrap(dir string, b bootstrap) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return e
	}
	p := filepath.Join(dir, "bootstrap.json")
	if e = os.WriteFile(p+".tmp", raw, 0600); e != nil {
		return e
	}
	return os.Rename(p+".tmp", p)
}
