package grab

import "testing"

func TestChaitinSeverityNotTitleLanguage(t *testing.T) {
	c := NewChaitinCrawler()
	for _, title := range []string{"CVE-2026-12345", "Example Product vulnerability", "中文漏洞"} {
		if !c.IsValuable(&VulnInfo{Title: title, Severity: High}) {
			t.Fatal(title)
		}
	}
	if c.IsValuable(&VulnInfo{Title: "中文漏洞", Severity: Low}) {
		t.Fatal("low severity accepted")
	}
}
