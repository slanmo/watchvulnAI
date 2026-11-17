package platform

import (
	"regexp"
	"strings"
)

var markdownHeading = regexp.MustCompile(`^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$`)
var bulletItem = regexp.MustCompile(`^(\s*)[-*+]\s+(.+)$`)

func feishuMarkdown(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if m := markdownHeading.FindStringSubmatch(line); len(m) == 2 {
			lines[i] = "**" + strings.TrimSpace(m[1]) + "**"
			continue
		}
		if m := bulletItem.FindStringSubmatch(line); len(m) == 3 {
			lines[i] = m[1] + "• " + m[2]
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "---" || trim == "***" || trim == "___" {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}
