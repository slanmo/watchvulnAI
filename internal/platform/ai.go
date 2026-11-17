package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type aiAnalysis struct {
	Summary  string   `json:"summary"`
	Risks    []string `json:"risks"`
	Actions  []string `json:"actions"`
	Analysis string   `json:"analysis"`
}

func (e *Engine) Generate(ctx context.Context, kind string) (report Report, err error) {
	if kind != "daily" && kind != "weekly" && kind != "custom" {
		return report, errors.New("报告类型必须为daily或weekly")
	}
	if !e.generateMu.TryLock() {
		return report, errors.New("报告正在生成")
	}
	defer e.generateMu.Unlock()
	id, _ := ctx.Value(reportContextKey{}).(string)
	if id == "" {
		id = ID()
	}
	report = Report{ID: id, Kind: kind, Title: "漏洞风险分析 · " + kind, Status: "generating", CreatedAt: time.Now().UTC(), VulnerabilityIDs: []string{}}
	if err = e.store.PutReport(report); err != nil {
		return report, err
	}
	ctx = context.WithValue(ctx, reportContextKey{}, id)
	ctx = context.WithValue(ctx, callWriterKey{}, e.callEvent)
	defer func() {
		if err != nil {
			report.Status = "failed"
			report.Error = err.Error()
			if errors.Is(err, context.Canceled) {
				report.Status = "cancelled"
				report.Error = "用户取消或服务停止，生成已终止"
			}
			_ = e.event(ctx, "error", err.Error())
			if saveErr := e.store.PutReport(report); saveErr != nil {
				err = fmt.Errorf("%v; 保存失败状态: %w", err, saveErr)
			}
		}
	}()
	cfg, err := taskConfig(ctx, e.store)
	if err != nil {
		return report, err
	}
	if !cfg.AI.Enabled {
		return report, errors.New("AI未启用")
	}
	if err = validURL(cfg.Branding.PublicURL, true); err != nil {
		return report, errors.New("生成报告前请配置公开访问URL")
	}
	now := time.Now().In(reportZone)
	days := 1
	label := "日报"
	if kind == "weekly" {
		days = 7
		label = "周报"
	}
	start := now.AddDate(0, 0, -days)
	end := now
	if kind == "custom" {
		p, ok := ctx.Value(reportPeriodKey{}).(reportPeriod)
		if !ok {
			return report, errors.New("请指定自定义周期")
		}
		start = p.Start
		end = p.End
		label = "自定义周期报告"
	}
	all, err := e.store.Vulnerabilities()
	if err != nil {
		return report, err
	}
	items := []Vulnerability{}
	seen := map[string]bool{}
	for _, v := range all {
		if !v.Selected || v.CreatedAt.Before(start) || !v.CreatedAt.Before(end) {
			continue
		}
		{
			cve := strings.ToUpper(strings.TrimSpace(v.CVE))
			if cfg.Collector.EnableCVEFilter && cve != "" && seen[cve] {
				continue
			}
			if cve != "" {
				seen[cve] = true
			}
			items = append(items, v)
		}
	}
	if len(items) == 0 {
		return report, errors.New("该周期没有通过筛选的漏洞，不生成空报告")
	}
	report = Report{ID: id, Kind: kind, Title: "漏洞风险分析" + label + " · " + now.Format("2006-01-02"), Status: "generating", CreatedAt: now, PeriodStart: start, PeriodEnd: end, VulnerabilityIDs: []string{}}
	for _, v := range items {
		report.VulnerabilityIDs = append(report.VulnerabilityIDs, v.ID)
	}
	if err = e.store.PutReport(report); err != nil {
		return report, err
	}
	stats := reportStatistics(items)
	cfg.AI.Prompt += "\n" + statisticsPrompt(stats)
	analysis, err := analyzeBatches(ctx, cfg.AI, items)
	if err != nil {
		return report, err
	}
	report.Summary = analysis.Summary
	var html bytes.Buffer
	view := struct {
		Report   Report
		Analysis aiAnalysis
		Items    []Vulnerability
		Stats    ReportStatistics
		BaseURL  string
	}{report, analysis, items, stats, strings.TrimRight(cfg.Branding.PublicURL, "/")}
	if err = reportTemplate.Execute(&html, view); err != nil {
		return report, err
	}
	report.HTML = html.String()
	link := strings.TrimRight(cfg.Branding.PublicURL, "/") + "/api/reports/" + url.PathEscape(report.ID) + "/html"
	report.FeishuCard, report.DingtalkCard = notificationCards(report.Title, analysis.Summary, link, &report)
	report.Status = "ready"
	err = e.store.PutReport(report)
	return report, err
}
