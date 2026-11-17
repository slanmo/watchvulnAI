package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetryAnalysis(t *testing.T) {
	calls := 0
	_, err := retryAnalysis(context.Background(), 5, 0, func(context.Context) (aiAnalysis, error) {
		calls++
		return aiAnalysis{}, errors.New("timeout awaiting headers")
	})
	if calls != 6 || err == nil || !strings.Contains(err.Error(), "5次失败重试") {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	calls = 0
	_, err = retryAnalysis(context.Background(), 5, 0, func(context.Context) (aiAnalysis, error) {
		calls++
		if calls < 3 {
			return aiAnalysis{}, errors.New("temporary")
		}
		return aiAnalysis{Summary: "ok"}, nil
	})
	if calls != 3 || err != nil {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	_, err = retryAnalysis(ctx, 5, 0, func(context.Context) (aiAnalysis, error) { calls++; return aiAnalysis{}, nil })
	if calls != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestFailedReportPersistsReason(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(504) }))
	defer remote.Close()
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.Branding.PublicURL = "http://localhost:8080"
	cfg.AI.Enabled = true
	cfg.AI.APIKey = "test"
	cfg.AI.BaseURL = remote.URL
	cfg.AI.RetryCount = 0
	if err = st.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = st.PutVulnerability(Vulnerability{ID: "test", Selected: true, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r, err := NewEngine(st).Generate(context.Background(), "daily")
	if err == nil {
		t.Fatal("expected failure")
	}
	saved, err := st.Report(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Status != "failed" || !strings.Contains(saved.Error, "HTTP 504") || !strings.Contains(saved.Error, "批次1-1") {
		t.Fatalf("%+v", saved)
	}
}

func TestRetryConfigDefaultAndZero(t *testing.T) {
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	if err = st.put("config", "main", map[string]any{"ai": map[string]any{"enabled": false}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.Config()
	if err != nil || cfg.AI.RetryCount != 5 {
		t.Fatal(cfg.AI, err)
	}
	cfg.AI.RetryCount = 0
	if err = st.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err = st.Config()
	if err != nil || cfg.AI.RetryCount != 0 {
		t.Fatal(cfg.AI, err)
	}
}
