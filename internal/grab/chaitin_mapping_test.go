package grab

import (
	"context"
	"github.com/imroc/req/v3"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChaitinEnglishFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"code":0,"data":{"list":[{"id":"uuid","ct_id":"CT-1","title":"CVE-2026-1","summary":"","summary_en":"English description","fix_steps":"Upgrade per vendor","severity":"medium","cve_id":"CVE-2026-1","disclosure_date":"2026-01-02","created_at":"2026-02-03T00:00:00+08:00","references":"https://example.com"}]}}`))
	}))
	defer srv.Close()
	client := req.C()
	client.OnBeforeRequest(func(_ *req.Client, r *req.Request) error {
		r.RawURL = strings.Replace(r.RawURL, "https://stack.chaitin.com", srv.URL, 1)
		return nil
	})
	c := NewChaitinCrawler().(*ChaitinCrawler)
	c.client = client
	items, err := c.GetUpdate(context.Background(), 1)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	v := items[0]
	if v.Description != "English description" || v.Solutions != "Upgrade per vendor" || v.Disclosure != "2026-01-02" || v.Severity != Medium {
		t.Fatal(v)
	}
}
