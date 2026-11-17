package platform

import "strings"

func ruleName(r Rule) string {
	if name := strings.TrimSpace(r.Name); name != "" {
		return name
	}
	prefix := "未命名黑名单"
	if r.Kind == "white" {
		prefix = "未命名白名单"
	}
	return prefix
}
