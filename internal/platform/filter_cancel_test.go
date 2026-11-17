package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestReportCancellationAndSelectedOnly(t *testing.T) {
	entered := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	defer remote.Close()
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.AI.Enabled = true
	cfg.AI.BaseURL = remote.URL
	cfg.AI.APIKey = "test"
	cfg.Branding.PublicURL = "https://example.com"
	st.SaveConfig(cfg)
	st.PutVulnerability(Vulnerability{ID: "pass", Selected: true, CreatedAt: time.Now()})
	st.PutVulnerability(Vulnerability{ID: "exclude", Valuable: true, Selected: false, CreatedAt: time.Now()})
	e := NewEngine(st)
	report, err := e.StartReport(context.Background(), "daily", false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request not started")
	}
	if err = e.CancelReport(report.ID); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); ; {
		r, err := st.Report(report.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status == "cancelled" {
			if len(r.VulnerabilityIDs) != 1 || r.VulnerabilityIDs[0] != "pass" {
				t.Fatal(r.VulnerabilityIDs)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(r)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func TestCallOutputIsSingleBlock(t *testing.T) {
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	e := NewEngine(st)
	ctx := context.WithValue(context.Background(), reportContextKey{}, "r")
	ctx = context.WithValue(ctx, callContextKey{}, "call")
	for _, part := range []string{"hello", " ", "world"} {
		if err = e.callEvent(ctx, "delta", part); err != nil {
			t.Fatal(err)
		}
	}
	rows := []ReportEvent{}
	st.all("report_event", &rows)
	if len(rows) != 1 || rows[0].Content != "hello world" {
		t.Fatal(rows)
	}
}
