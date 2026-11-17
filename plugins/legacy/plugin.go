package legacy

import legacycli "github.com/zema1/watchvuln/plugins/legacy/cli"

type Info struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Mode         string   `json:"mode"`
	Capabilities []string `json:"capabilities"`
	Entry        string   `json:"entry"`
}

func Describe() Info {
	return Info{ID: "legacy", Name: "旧版兼容插件", Mode: "builtin", Entry: "watchvuln plugin legacy [旧版参数]", Capabilities: []string{"YAML/JSON配置及环境变量", "SQLite/MySQL/PostgreSQL旧存储", "旧版白黑名单文件", "diff单次执行与启动通知", "GitHub仓库与Nuclei PR检索", "CtInternal私有推送", "旧版RawMessage Webhook协议"}}
}
func Run(version string) { legacycli.Run(version) }
