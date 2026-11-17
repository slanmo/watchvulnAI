package platform

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeliveryRetentionProtectsRetries(t *testing.T) {
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.DeliveryRetentionDays = 1
	if err = st.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	for _, d := range []Delivery{{ID: "sent", Status: "sent"}, {ID: "pending", Status: "pending"}, {ID: "retry", Status: "failed", Attempts: 1}, {ID: "exhausted", Status: "failed", Attempts: 8}} {
		d.CreatedAt = time.Now().AddDate(0, 0, -3)
		if err = st.PutDelivery(d); err != nil {
			t.Fatal(err)
		}
	}
	if err = NewEngine(st).PruneDeliveries(); err != nil {
		t.Fatal(err)
	}
	rows, err := st.Deliveries()
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	for _, d := range rows {
		if d.ID != "pending" && d.ID != "retry" {
			t.Fatal(d)
		}
	}
}
func TestGenerateSolutionPersistsAndDoesNotOverwrite(t *testing.T) {
	calls := 0
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"impact":"受影响版本","risk":"存在利用风险","reproduction":"构造特定请求","remediation":"参考厂商公告升级；升级前备份并验证访问控制。"}`}}}})
	}))
	defer remote.Close()
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "solution.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.AI.Enabled = true
	cfg.Collector.AISolution = true
	cfg.AI.BaseURL = remote.URL
	cfg.AI.APIKey = "test"
	cfg.AI.RetryCount = 0
	st.SaveConfig(cfg)
	st.PutVulnerability(Vulnerability{ID: "v", Title: "测试漏洞", Selected: false})
	s := &Server{store: st, engine: NewEngine(st), ctx: context.Background()}
	router := gin.New()
	router.POST("/vulnerabilities/:id/solution", s.generateSolution)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/vulnerabilities/v/solution", nil))
	if w.Code != 409 {
		t.Fatal("excluded vulnerability must be rejected", w.Code, w.Body.String())
	}
	st.put("vulnerability", "v", Vulnerability{ID: "v", Title: "测试漏洞", Selected: true})
	req := httptest.NewRequest("POST", "/vulnerabilities/v/solution", nil).WithContext(context.Background())
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var v Vulnerability
	for deadline := time.Now().Add(3 * time.Second); ; {
		st.get("vulnerability", "v", &v)
		if v.AIAnalysis != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background task not finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v.AIAnalysis == nil || !strings.Contains(v.AIAnalysis.Remediation, "升级") || !v.Selected {
		t.Fatal(v)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/vulnerabilities/v/solution", nil))
	if w.Code != 409 || calls != 1 {
		t.Fatal(w.Code, calls)
	}
}
