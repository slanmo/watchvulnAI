package platform

import "strings"

func sourceErrorMessage(message string) string {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "aliyun_waf") || strings.Contains(lower, "aliyuncaptcha") || strings.Contains(lower, "waf bypass failed") {
		return "AVD来源要求访问验证，暂时无法自动采集；请稍后重试或在漏洞采集中暂时关闭AVD，其他来源不受影响"
	}
	if i := strings.Index(lower, "<!doctype html"); i >= 0 {
		message = message[:i] + "上游返回HTML页面，未获取到有效漏洞数据"
	} else if i := strings.Index(lower, "<html"); i >= 0 {
		message = message[:i] + "上游返回HTML页面，未获取到有效漏洞数据"
	}
	if len([]rune(message)) > 1500 {
		return string([]rune(message)[:1500]) + "…"
	}
	return message
}
