package platform

import (
	"testing"
	"time"
)

func TestReportStatisticsAndPeriod(t *testing.T) {
	now := time.Date(2026, 11, 10, 1, 0, 0, 0, time.UTC)
	s := reportStatistics([]Vulnerability{{Title: "MinIO漏洞", Severity: "严重", CreatedAt: now}, {Title: "Redis漏洞", Severity: "高危", CreatedAt: now}, {Title: "未知产品", CreatedAt: now}})
	if s.Total != 3 || s.High != 2 || s.Unknown != 1 || len(s.Components) != 3 || s.Trend[0].Label != "2026-11-10" {
		t.Fatal(s)
	}
	p, err := parseReportPeriod("2026-01-01", "2026-01-02")
	if err != nil {
		t.Fatal(err)
	}
	_, offset := p.Start.Zone()
	if offset != 8*3600 || p.End.Sub(p.Start) != 48*time.Hour {
		t.Fatal(p)
	}
	if _, err = parseReportPeriod("2026-01-02", "2026-01-01"); err == nil {
		t.Fatal("reversed range accepted")
	}
}
