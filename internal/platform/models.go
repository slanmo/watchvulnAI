package platform

import "time"

type Branding struct {
	Title     string `json:"title"`
	Logo      string `json:"logo"`
	PublicURL string `json:"public_url"`
}
type CollectorConfig struct {
	Enabled         bool     `json:"enabled"`
	Sources         []string `json:"sources"`
	Interval        string   `json:"interval"`
	Proxy           string   `json:"proxy"`
	SkipTLSVerify   bool     `json:"skip_tls_verify"`
	EnableCVEFilter bool     `json:"enable_cve_filter"`
	NoFilter        bool     `json:"no_filter"`
	NoGithubSearch  bool     `json:"no_github_search"`
	NoSleep         bool     `json:"no_sleep"`
	WindowStart     string   `json:"window_start"`
	WindowEnd       string   `json:"window_end"`
	AISolution      bool     `json:"ai_solution"`
}
type Rule struct {
	Name    string   `json:"name"`
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Kind    string   `json:"kind"`
	Fields  []string `json:"fields"`
	Pattern string   `json:"pattern"`
	Regex   bool     `json:"regex"`
}
type Notification struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Enabled  bool              `json:"enabled"`
	Settings map[string]string `json:"settings"`
}
type AIConfig struct {
	Provider       string `json:"provider"`
	Enabled        bool   `json:"enabled"`
	BaseURL        string `json:"base_url"`
	APIKey         string `json:"api_key"`
	Model          string `json:"model"`
	Daily          bool   `json:"daily"`
	Weekly         bool   `json:"weekly"`
	Hour           int    `json:"hour"`
	Weekday        int    `json:"weekday"`
	Timezone       string `json:"timezone"`
	Prompt         string `json:"prompt"`
	MaxItems       int    `json:"max_items"`
	RetryCount     int    `json:"retry_count"`
	RetentionDays  int    `json:"retention_days"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}
type OAuthConfig struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Issuer       string `json:"issuer,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
}
type LDAPConfig struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`
	StartTLS     bool   `json:"start_tls"`
}
type AuthConfig struct {
	ReportAccess string      `json:"report_access"`
	OIDC         OAuthConfig `json:"oidc"`
	LDAP         LDAPConfig  `json:"ldap"`
	Feishu       OAuthConfig `json:"feishu"`
	Dingtalk     OAuthConfig `json:"dingtalk"`
}
type Config struct {
	RetentionVersion      int             `json:"retention_version"`
	Branding              Branding        `json:"branding"`
	Collector             CollectorConfig `json:"collector"`
	Rules                 []Rule          `json:"rules"`
	Notifications         []Notification  `json:"notifications"`
	DeliveryRetentionDays int             `json:"delivery_retention_days"`
	AI                    AIConfig        `json:"ai"`
	Auth                  AuthConfig      `json:"auth"`
}
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	Provider     string    `json:"provider"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}
type Vulnerability struct {
	ID           string          `json:"id"`
	Source       string          `json:"source"`
	SourceID     string          `json:"source_id"`
	Title        string          `json:"title"`
	CVE          string          `json:"cve"`
	Tags         []string        `json:"tags"`
	Severity     string          `json:"severity"`
	Reasons      []string        `json:"reasons"`
	References   []string        `json:"references"`
	Description  string          `json:"description"`
	Solution     string          `json:"solution"`
	URL          string          `json:"url"`
	PublishedAt  string          `json:"published_at"`
	CreatedAt    time.Time       `json:"created_at"`
	Valuable     bool            `json:"valuable"`
	Selected     bool            `json:"selected"`
	FilterReason string          `json:"filter_reason"`
	AIAnalysis   *VulnAIAnalysis `json:"ai_analysis,omitempty"`
}
type VulnAIAnalysis struct {
	Impact       string `json:"impact"`
	Risk         string `json:"risk"`
	Reproduction string `json:"reproduction"`
	Remediation  string `json:"remediation"`
}
type Report struct {
	ID               string         `json:"id"`
	Kind             string         `json:"kind"`
	Title            string         `json:"title"`
	Summary          string         `json:"summary"`
	HTML             string         `json:"html,omitempty"`
	Status           string         `json:"status"`
	Error            string         `json:"error,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	PeriodStart      time.Time      `json:"period_start"`
	PeriodEnd        time.Time      `json:"period_end"`
	VulnerabilityIDs []string       `json:"vulnerability_ids"`
	FeishuCard       map[string]any `json:"feishu_card,omitempty"`
	DingtalkCard     map[string]any `json:"dingtalk_card,omitempty"`
}
type Delivery struct {
	ID            string         `json:"id"`
	ReportID      string         `json:"report_id"`
	ChannelID     string         `json:"channel_id"`
	Status        string         `json:"status"`
	Error         string         `json:"error"`
	CreatedAt     time.Time      `json:"created_at"`
	Title         string         `json:"title,omitempty"`
	Text          string         `json:"text,omitempty"`
	Link          string         `json:"link,omitempty"`
	Attempts      int            `json:"attempts"`
	NextAttempt   time.Time      `json:"next_attempt"`
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`
}

func DefaultConfig() Config {
	return Config{RetentionVersion: 1, DeliveryRetentionDays: 7, Branding: Branding{Title: "WatchVuln AI"}, Collector: CollectorConfig{Sources: []string{"avd", "nox", "oscs", "threatbook", "seebug", "struts2", "kev", "venustech", "chaitin"}, Interval: "30m", EnableCVEFilter: true, NoGithubSearch: true, NoSleep: true}, Rules: []Rule{}, Notifications: []Notification{}, AI: AIConfig{RetentionDays: 7, BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", Hour: 9, Weekday: 1, Timezone: "Asia/Shanghai", MaxItems: 100, RetryCount: 5, TimeoutSeconds: 300}, Auth: AuthConfig{ReportAccess: "authenticated", LDAP: LDAPConfig{UserFilter: "(uid={username})"}}}
}
