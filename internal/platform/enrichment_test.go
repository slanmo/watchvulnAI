package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrichBeforePush(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "AI failure falls back"}[failure], func(t *testing.T) {
			calls := 0
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if failure {
					w.WriteHeader(503)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"impact":"受影响组件与版本","risk":"可能被未授权利用","reproduction":"发送特定请求验证","remediation":"升级到厂商修复版本"}`}}}})
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
			cfg.AI.RetryCount = 0
			cfg.Collector.AISolution = true
			v := Vulnerability{ID: "v", Title: "test", Selected: true, CreatedAt: time.Now()}
			st.PutVulnerability(v)
			result, err := NewEngine(st).enrichBeforePush(context.Background(), cfg, v)
			if err != nil {
				t.Fatal("AI failure must not block push", err)
			}
			if calls != 1 {
				t.Fatal(calls)
			}
			if failure && result.AIAnalysis != nil {
				t.Fatal(result.AIAnalysis)
			}
			if !failure && (result.AIAnalysis == nil || !strings.Contains(result.AIAnalysis.Impact, "受影响组件")) {
				t.Fatal(result)
			}
			jobs := []SolutionJob{}
			st.all("solution_job", &jobs)
			if len(jobs) != 1 || (failure && jobs[0].Status != "failed") || (!failure && jobs[0].Status != "ready") {
				t.Fatal(jobs)
			}
		})
	}
}
