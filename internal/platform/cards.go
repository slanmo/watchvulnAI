package platform

import (
	"fmt"
	"strings"
)

func cardExcerpt(text string, limit int) string {
	r := []rune(strings.TrimSpace(text))
	if len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return string(r)
}
func notificationCards(title, text, link string, report *Report) (map[string]any, map[string]any) {
	category := "漏洞情报"
	button := "查看漏洞公告"
	meta := "WatchVuln · 安全情报通知"
	if report != nil {
		category = "AI 风险分析日报"
		if report.Kind == "weekly" {
			category = "AI 风险分析周报"
		}
		button = "查看完整分析报告"
		meta = fmt.Sprintf("%d 条漏洞 · %s", len(report.VulnerabilityIDs), report.CreatedAt.Format("2006-01-02 15:04"))
	}
	summary := cardExcerpt(text, 1200)
	elements := []any{map[string]any{"tag": "div", "text": map[string]string{"tag": "lark_md", "content": "**" + category + "**\n\n" + feishuMarkdown(summary)}}, map[string]any{"tag": "hr"}, map[string]any{"tag": "note", "elements": []any{map[string]string{"tag": "plain_text", "content": meta}}}}
	if link != "" {
		elements = append(elements, map[string]any{"tag": "action", "actions": []any{map[string]any{"tag": "button", "text": map[string]string{"tag": "plain_text", "content": button}, "url": link, "type": "primary"}}})
	}
	feishu := map[string]any{"config": map[string]any{"wide_screen_mode": true, "enable_forward": true}, "header": map[string]any{"template": "blue", "title": map[string]string{"tag": "plain_text", "content": cardExcerpt(title, 120)}}, "elements": elements}
	action := map[string]string{"title": cardExcerpt(title, 120), "text": "### " + cardExcerpt(title, 120) + "\n\n> " + category + "\n\n" + summary + "\n\n---\n\n" + meta, "hideAvatar": "0"}
	if link != "" {
		action["singleTitle"] = button
		action["singleURL"] = link
	}
	ding := map[string]any{"msgtype": "actionCard", "actionCard": action}
	return feishu, ding
}
