package platform

import (
	"strings"
	"testing"
)

func TestFeishuHeadings(t *testing.T) {
	text := feishuMarkdown("# 标题\n\n### 漏洞描述\n正文\n---\n## 修复方案\n升级")
	if strings.Contains(text, "#") || strings.Contains(text, "---") || !strings.Contains(text, "**修复方案**") {
		t.Fatal(text)
	}
	listed := feishuMarkdown("**官方升级**\n- 升级到厂商修复版本\n* 限制管理接口访问\n+ 临时关闭公网暴露\n正文-保留")
	for _, banned := range []string{"\n- ", "\n* ", "\n+ "} {
		if strings.Contains(listed, banned) {
			t.Fatal("bullet marker must be converted", listed)
		}
	}
	if !strings.Contains(listed, "• 升级到厂商修复版本") || !strings.Contains(listed, "正文-保留") {
		t.Fatal(listed)
	}
	v := Vulnerability{Title: "示例漏洞", Description: "### 上游标题\n内容"}
	f, _ := vulnerabilityCards(v)
	elements := f["elements"].([]any)
	body := elements[0].(map[string]any)["text"].(map[string]string)["content"]
	if strings.Contains(body, "###") || strings.Contains(body, v.Title) {
		t.Fatal(body)
	}
}
