package platform

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRefilterHistory(t *testing.T) {
	s, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	cfg := DefaultConfig()
	s.SaveConfig(cfg)
	s.PutVulnerability(Vulnerability{ID: "a", Title: "MinIO漏洞", Valuable: true, Selected: true, CreatedAt: time.Now()})
	s.PutVulnerability(Vulnerability{ID: "b", Title: "Redis漏洞", Valuable: true, Selected: false, FilterReason: "命中黑名单: Redis", CreatedAt: time.Now()})
	cfg.Rules = []Rule{{Enabled: true, Kind: "black", Fields: []string{"title"}, Pattern: "MinIO"}}
	n, err := s.SaveConfigAndRefilter(cfg)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	var a, b Vulnerability
	s.get("vulnerability", "a", &a)
	s.get("vulnerability", "b", &b)
	if a.Selected || !b.Selected {
		t.Fatal(a, b)
	}
	rows, _ := s.Deliveries()
	if len(rows) != 0 {
		t.Fatal("refilter sent notifications")
	}
}
