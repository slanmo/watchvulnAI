package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestManualPushAIThenDelivery(t *testing.T) {
	analyzed := false
	delivered := make(chan bool, 1)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chat/completions" {
			analyzed = true
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"choices":[{"message":{"content":"{\"impact\":\"组件影响\",\"risk\":\"风险\",\"reproduction\":\"仅验证\",\"remediation\":\"升级\"}"}}]}`))
			return
		}
		delivered <- analyzed
		w.Write([]byte(`{}`))
	}))
	defer remote.Close()
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.Collector.AISolution = true
	cfg.AI.Enabled = true
	cfg.AI.BaseURL = remote.URL
	cfg.AI.RetryCount = 0
	cfg.Notifications = []Notification{{ID: "n", Enabled: true, Type: "webhook", Settings: map[string]string{"url": remote.URL + "/push"}}}
	st.SaveConfig(cfg)
	st.PutVulnerability(Vulnerability{ID: "v", Selected: true, Solution: "厂商方案"})
	e := NewEngine(st)
	if _, err = e.StartPush(context.Background(), "v"); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-delivered:
		if !ok {
			t.Fatal("delivery before AI")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no delivery")
	}
	var v Vulnerability
	st.get("vulnerability", "v", &v)
	if v.Solution != "厂商方案" || v.AIAnalysis == nil {
		t.Fatal(v)
	}
}
