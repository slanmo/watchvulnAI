package platform

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestBaselineMarkerAndSummary(t *testing.T) {
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.Branding.PublicURL = "https://example.com"
	st.SaveConfig(cfg)
	e := NewEngine(st)
	needed, err := e.needsBaseline()
	if err != nil || !needed {
		t.Fatal(needed, err)
	}
	st.PutVulnerability(Vulnerability{ID: "v", Selected: true, CreatedAt: time.Now()})
	if err = e.finishBaseline(context.Background(), cfg, nil); err != nil {
		t.Fatal(err)
	}
	needed, err = e.needsBaseline()
	if err != nil || needed {
		t.Fatal(needed, err)
	}
	rows, _ := st.Deliveries()
	if len(rows) != 0 {
		t.Fatal("no configured channels must not create deliveries")
	}
}
func TestExistingDatabaseDoesNotRepeatBaseline(t *testing.T) {
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "existing.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	st.PutVulnerability(Vulnerability{ID: "existing"})
	needed, err := NewEngine(st).needsBaseline()
	if err != nil || needed {
		t.Fatal(needed, err)
	}
}
