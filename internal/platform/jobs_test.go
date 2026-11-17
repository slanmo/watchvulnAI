package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackgroundReportSnapshotEventsAndRetention(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"summary\\\":\\\"摘要\\\",\\\"analysis\\\":\\\"分析\\\",\\\"risks\\\":[],\\\"actions\\\":[]}\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer remote.Close()
	store, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	cfg := DefaultConfig()
	cfg.Branding.PublicURL = "https://example.com"
	cfg.AI.Enabled = true
	cfg.AI.BaseURL = remote.URL
	cfg.AI.APIKey = "secret"
	cfg.AI.RetryCount = 0
	if err = store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	store.PutVulnerability(Vulnerability{ID: "v", Selected: true, CreatedAt: time.Now()})
	engine := NewEngine(store)
	r, err := engine.StartReport(context.Background(), "daily", false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("background not started")
	}
	cfg.AI.BaseURL = "http://invalid.example"
	if err = store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.StartReport(context.Background(), "weekly", false); err == nil {
		t.Fatal("duplicate report allowed")
	}
	if err = engine.DeleteReport(r.ID); err == nil {
		t.Fatal("running report deleted")
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		r, err = store.Report(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status == "ready" {
			break
		}
		if r.Status == "failed" || time.Now().After(deadline) {
			t.Fatal(r)
		}
		time.Sleep(10 * time.Millisecond)
	}
	events := []ReportEvent{}
	if err = store.all("report_event", &events); err != nil {
		t.Fatal(err)
	}
	hasPrompt, hasDelta := false, false
	for _, v := range events {
		hasPrompt = hasPrompt || v.Kind == "prompt"
		hasDelta = hasDelta || (v.Kind == "output" && v.CallID != "")
		if strings.Contains(v.Content, "Bearer secret") {
			t.Fatal("key leaked")
		}
	}
	if !hasPrompt || !hasDelta {
		t.Fatal(events)
	}
	r.CreatedAt = time.Now().AddDate(0, 0, -3)
	store.PutReport(r)
	cfg.AI.RetentionDays = 1
	store.SaveConfig(cfg)
	if err = engine.PruneReports(); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Report(r.ID); err == nil {
		t.Fatal("expired report retained")
	}
	events = nil
	store.all("report_event", &events)
	if len(events) != 0 {
		t.Fatal("orphan events")
	}
}
