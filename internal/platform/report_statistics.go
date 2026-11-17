package platform

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type StatBar struct {
	Label   string
	Count   int
	Percent float64
}
type ReportStatistics struct {
	Total, High, Unknown        int
	HighPercent                 float64
	Risk                        string
	Severity, Components, Trend []StatBar
}

func severityGroup(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "严重", "critical":
		return "严重"
	case "高危", "high":
		return "高危"
	case "中危", "medium":
		return "中危"
	case "低危", "low":
		return "低危"
	default:
		return "未知"
	}
}

var componentPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Linux", regexp.MustCompile(`(?i)\blinux\b`)}, {"Windows", regexp.MustCompile(`(?i)\bwindows\b`)}, {"Apache", regexp.MustCompile(`(?i)\bapache\b`)}, {"WordPress", regexp.MustCompile(`(?i)\bwordpress\b`)}, {"Redis", regexp.MustCompile(`(?i)\bredis\b`)}, {"MinIO", regexp.MustCompile(`(?i)\bminio\b`)}, {"GitLab", regexp.MustCompile(`(?i)\bgitlab\b`)}, {"Jenkins", regexp.MustCompile(`(?i)\bjenkins\b`)}, {"Spring", regexp.MustCompile(`(?i)\bspring\b`)}, {"PHP", regexp.MustCompile(`(?i)\bphp\b`)}, {"Nginx", regexp.MustCompile(`(?i)\bnginx\b`)}, {"Docker", regexp.MustCompile(`(?i)\bdocker\b`)}, {"Kubernetes", regexp.MustCompile(`(?i)\bkubernetes\b`)}, {"OpenSSL", regexp.MustCompile(`(?i)\bopenssl\b`)}, {"Tomcat", regexp.MustCompile(`(?i)\btomcat\b`)},
}

func reportComponent(v Vulnerability) string {
	for _, p := range componentPatterns {
		if p.Pattern.MatchString(v.Title + " " + strings.Join(v.Tags, " ")) {
			return p.Name
		}
	}
	return "其他/组件待确认"
}
func statisticBars(m map[string]int, total int, rank bool) []StatBar {
	rows := []StatBar{}
	for label, count := range m {
		rows = append(rows, StatBar{label, count, float64(count) * 100 / float64(max(1, total))})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rank && rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Label < rows[j].Label
	})
	return rows
}
func reportStatistics(items []Vulnerability) ReportStatistics {
	s := ReportStatistics{Total: len(items), Risk: "待确认"}
	severity, components, trend := map[string]int{}, map[string]int{}, map[string]int{}
	for _, v := range items {
		level := severityGroup(v.Severity)
		severity[level]++
		components[reportComponent(v)]++
		trend[v.CreatedAt.In(reportZone).Format("2006-01-02")]++
		if level == "严重" || level == "高危" {
			s.High++
		}
		if level == "未知" {
			s.Unknown++
		}
	}
	s.HighPercent = float64(s.High) * 100 / float64(max(1, s.Total))
	if severity["严重"] > 0 {
		s.Risk = "高风险（含严重漏洞）"
	} else if s.High > 0 {
		s.Risk = "高风险"
	} else if severity["中危"] > 0 {
		s.Risk = "中风险"
	} else if severity["低危"] > 0 && s.Unknown == 0 {
		s.Risk = "低风险"
	}
	for _, label := range []string{"严重", "高危", "中危", "低危", "未知"} {
		s.Severity = append(s.Severity, StatBar{label, severity[label], float64(severity[label]) * 100 / float64(max(1, s.Total))})
	}
	s.Components = statisticBars(components, s.Total, true)
	s.Trend = statisticBars(trend, s.Total, false)
	return s
}
func statisticsPrompt(s ReportStatistics) string {
	return fmt.Sprintf("程序核实统计：总计%d条；严重及高危%d条，占%.1f%%；等级未知%d条；总体分级%s。请按执行摘要、主要风险、组件集中度和业务解释组织分析，通俗清楚；不要编造资产受影响数量、利用概率或统计显著性。报告以全局总结为主，不逐条重复描述，不输出具体修复步骤，用户将通过漏洞详细页查看方案。", s.Total, s.High, s.HighPercent, s.Unknown, s.Risk)
}
