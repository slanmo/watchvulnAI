package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Server{dir: t.TempDir(), assets: "../../frontend/dist", ctx: ctx, sessions: map[string]session{}, states: map[string]oauthState{}, attempts: map[string][]time.Time{}}
}
func request(t *testing.T, h http.Handler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &b)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestSetupLoginPermissions(t *testing.T) {
	s := testServer(t)
	h := s.router()
	w := request(t, h, "POST", "/api/setup", map[string]string{"database": "sqlite", "password": "Root_2025", "title": "安全平台"}, nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	t.Cleanup(func() { s.store.db.Close() })
	if w = request(t, h, "POST", "/api/setup", map[string]string{}, nil); w.Code != 409 {
		t.Fatal(w.Code)
	}
	w = request(t, h, "POST", "/api/login", map[string]string{"username": "admin", "password": "Root_2025"}, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if w = request(t, h, "GET", "/api/config", nil, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = request(t, h, "POST", "/api/users", map[string]string{"username": "reader", "password": "Root_2025", "display_name": "只读用户"}, cookie)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	w = request(t, h, "POST", "/api/login", map[string]string{"username": "reader", "password": "Root_2025"}, nil)
	reader := w.Result().Cookies()[0]
	if w = request(t, h, "GET", "/api/config", nil, reader); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w = request(t, h, "GET", "/api/reports", nil, reader); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	r := httptest.NewRequest("PUT", "/api/config", strings.NewReader("{}"))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("CSRF not rejected")
	}
}
func TestRulesAllFields(t *testing.T) {
	v := Vulnerability{Title: "Product RCE", Tags: []string{"critical"}, Description: "affected", Solution: "upgrade"}
	for field, pattern := range map[string]string{"title": "rce", "tags": "critical", "description": "affected", "solution": "upgrade"} {
		ok, _ := RulesMatch(v, []Rule{{Enabled: true, Kind: "white", Fields: []string{field}, Pattern: pattern}})
		if !ok {
			t.Fatal(field)
		}
	}
	ok, _ := RulesMatch(v, []Rule{{Enabled: true, Kind: "white", Fields: []string{"title"}, Pattern: "RCE"}, {Enabled: true, Kind: "black", Fields: []string{"solution"}, Pattern: "upgrade"}})
	if ok {
		t.Fatal("black must override white")
	}
}
func TestAIReportAndRetry(t *testing.T) {
	calls := 0
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chat/completions" {
			calls++
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"summary":"风险摘要","risks":["风险"],"actions":["升级"],"analysis":"<script>alert(1)</script>完整分析"}`}}}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"code":0}`))
	}))
	defer remote.Close()
	st, err := OpenStore("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	cfg := DefaultConfig()
	cfg.Branding.PublicURL = "https://watch.example"
	cfg.AI.Enabled = true
	cfg.AI.BaseURL = remote.URL
	cfg.AI.APIKey = "secret"
	cfg.AI.MaxItems = 1
	cfg.Notifications = []Notification{{ID: "hook", Name: "hook", Type: "webhook", Enabled: true, Settings: map[string]string{"url": remote.URL}}}
	if err = st.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		st.PutVulnerability(Vulnerability{ID: id, Title: "漏洞" + id, Selected: true, CreatedAt: time.Now().UTC()})
	}
	engine := NewEngine(st)
	r, err := engine.Generate(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(r.VulnerabilityIDs) != 2 {
		t.Fatal(calls, r)
	}
	if strings.Contains(r.HTML, "<script>") {
		t.Fatal("unsafe HTML")
	}
	if r.FeishuCard == nil || r.DingtalkCard == nil {
		t.Fatal("missing cards")
	}
	if err = engine.SendReport(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	d, err := st.Deliveries()
	if err != nil || len(d) != 1 || d[0].Status != "sent" {
		t.Fatal(d, err)
	}
	d[0].Status = "failed"
	d[0].NextAttempt = time.Time{}
	st.PutDelivery(d[0])
	if err = engine.RetryDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	d, _ = st.Deliveries()
	if d[0].Status != "sent" || d[0].Attempts != 2 {
		t.Fatal(d)
	}
}
func TestMaskPreservesSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AI.APIKey = "secret"
	cfg.Notifications = []Notification{{Settings: map[string]string{"access_token": "token", "channel": "ops"}}}
	maskConfig(&cfg)
	if cfg.AI.APIKey != "********" || cfg.Notifications[0].Settings["access_token"] != "********" || cfg.Notifications[0].Settings["channel"] != "ops" {
		t.Fatal(cfg)
	}
}
