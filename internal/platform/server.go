package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/zema1/watchvuln/plugins/legacy"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type session struct {
	UserID  string
	Expires time.Time
}
type oauthState struct {
	Provider, Nonce string
	Expires         time.Time
}
type Server struct {
	mu          sync.RWMutex
	store       *Store
	engine      *Engine
	dir, assets string
	sessions    map[string]session
	states      map[string]oauthState
	attempts    map[string][]time.Time
	ctx         context.Context
}

func Run(ctx context.Context, addr, dir, assets string) error {
	s := &Server{dir: dir, assets: assets, ctx: ctx, sessions: map[string]session{}, states: map[string]oauthState{}, attempts: map[string][]time.Time{}}
	raw, e := os.ReadFile(filepath.Join(dir, "bootstrap.json"))
	if e == nil {
		var b bootstrap
		if e = json.Unmarshal(raw, &b); e != nil {
			return e
		}
		s.store, e = OpenStore(b.Database, b.DSN)
		if e != nil {
			return e
		}
		defer s.store.db.Close()
		s.startEngine()
	} else if !os.IsNotExist(e) {
		return e
	}
	h := &http.Server{Addr: addr, Handler: s.router(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 0, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.Shutdown(c)
	}()
	log.Printf("WatchVuln Web listening on %s", addr)
	e = h.ListenAndServe()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func (s *Server) startEngine() {
	s.engine = NewEngine(s.store)
	if err := s.engine.RecoverInterrupted(); err != nil {
		log.Printf("recover interrupted jobs: %v", err)
	}
	if err := s.engine.BootstrapCollection(s.ctx); err != nil {
		log.Printf("initial collection: %v", err)
	}
	go s.engine.Run(s.ctx)
}
func fail(c *gin.Context, status int, e any) {
	c.AbortWithStatusJSON(status, gin.H{"error": fmt.Sprint(e)})
}
func bind(c *gin.Context, v any) bool {
	if e := c.ShouldBindJSON(v); e != nil {
		fail(c, 400, "请求JSON格式错误")
		return false
	}
	return true
}
func randomToken() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func tokenKey(t string) string { b := sha256.Sum256([]byte(t)); return hex.EncodeToString(b[:]) }
func (s *Server) current(c *gin.Context) (User, bool) {
	t, e := c.Cookie("watchvuln_session")
	if e != nil {
		return User{}, false
	}
	s.mu.RLock()
	v, ok := s.sessions[tokenKey(t)]
	st := s.store
	s.mu.RUnlock()
	if !ok || time.Now().After(v.Expires) || st == nil {
		return User{}, false
	}
	u, e := st.User(v.UserID)
	return u, e == nil && !u.Disabled
}
func (s *Server) loginUser(c *gin.Context, u User) {
	t := randomToken()
	s.mu.Lock()
	for k, v := range s.sessions {
		if time.Now().After(v.Expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[tokenKey(t)] = session{u.ID, time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("watchvuln_session", t, 43200, "/", "", c.Request.TLS != nil, true)
}
func (s *Server) require(admin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		u, ok := s.current(c)
		if !ok {
			fail(c, 401, "请先登录")
			return
		}
		if admin && u.Role != "admin" {
			fail(c, 403, "需要管理员权限")
			return
		}
		c.Set("user", u)
		c.Next()
	}
}
func (s *Server) reportAccess(c *gin.Context) {
	s.mu.RLock()
	st := s.store
	s.mu.RUnlock()
	if st == nil {
		fail(c, 409, "尚未初始化")
		return
	}
	cfg, e := st.Config()
	if e != nil {
		fail(c, 500, e)
		return
	}
	if cfg.Auth.ReportAccess == "public" {
		c.Next()
		return
	}
	s.require(false)(c)
}
func (s *Server) router() *gin.Engine {
	r := gin.New()
	r.SetTrustedProxies(nil)
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "same-origin")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" && c.Request.Method != "OPTIONS" {
			o := c.GetHeader("Origin")
			if o != "" {
				u, e := url.Parse(o)
				if e != nil || u.Host != c.Request.Host {
					fail(c, 403, "禁止跨站写入请求")
					return
				}
			}
			if c.GetHeader("Sec-Fetch-Site") == "cross-site" {
				fail(c, 403, "禁止跨站请求")
				return
			}
		}
		c.Next()
	})
	r.GET("/api/status", s.status)
	r.GET("/api/logos/:name", s.serveLogo)
	r.POST("/api/setup", s.setup)
	r.POST("/api/login", s.login)
	r.POST("/api/logout", func(c *gin.Context) {
		t, _ := c.Cookie("watchvuln_session")
		s.mu.Lock()
		delete(s.sessions, tokenKey(t))
		s.mu.Unlock()
		c.SetCookie("watchvuln_session", "", -1, "/", "", false, true)
		c.JSON(200, gin.H{"ok": true})
	})
	r.GET("/api/oauth/:provider/start", s.oauthStart)
	r.GET("/api/oauth/:provider/callback", s.oauthCallback)
	a := r.Group("/api", s.require(false))
	a.GET("/me", func(c *gin.Context) { c.JSON(200, c.MustGet("user")) })
	a.PUT("/password", s.password)
	reports := r.Group("/api/reports", s.reportAccess)
	reports.GET("", func(c *gin.Context) {
		v, e := s.store.Reports()
		if e != nil {
			fail(c, 500, e)
			return
		}
		for i := range v {
			v[i].HTML = ""
		}
		c.JSON(200, v)
	})
	reports.GET("/:id", func(c *gin.Context) {
		v, e := s.store.Report(c.Param("id"))
		if e != nil {
			fail(c, 404, "报告不存在")
			return
		}
		c.JSON(200, v)
	})
	reports.GET("/:id/html", func(c *gin.Context) {
		v, e := s.store.Report(c.Param("id"))
		if e != nil {
			fail(c, 404, "报告不存在")
			return
		}
		c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
		c.Data(200, "text/html; charset=utf-8", []byte(v.HTML))
	})
	admin := r.Group("/api", s.require(true))
	admin.POST("/vulnerabilities/:id/push", func(c *gin.Context) {
		j, err := s.engine.StartPush(s.ctx, c.Param("id"))
		if err != nil {
			fail(c, 409, err)
			return
		}
		c.JSON(202, j)
	})
	admin.GET("/push-jobs", func(c *gin.Context) {
		rows := []PushJob{}
		if err := s.store.all("push_job", &rows); err != nil {
			fail(c, 500, err)
			return
		}
		c.JSON(200, rows)
	})
	admin.GET("/solution-jobs", func(c *gin.Context) {
		rows := []SolutionJob{}
		if err := s.store.all("solution_job", &rows); err != nil {
			fail(c, 500, err)
			return
		}
		c.JSON(200, rows)
	})
	r.GET("/api/vulnerabilities/:id", s.reportAccess, func(c *gin.Context) {
		var v Vulnerability
		if err := s.store.get("vulnerability", c.Param("id"), &v); err != nil {
			fail(c, 404, "漏洞不存在")
			return
		}
		c.JSON(200, v)
	})
	r.GET("/vulnerabilities/:id", s.reportAccess, s.vulnerabilityPage)
	admin.GET("/plugins", func(c *gin.Context) { c.JSON(200, []legacy.Info{legacy.Describe()}) })
	admin.GET("/config", func(c *gin.Context) {
		v, e := s.store.Config()
		if e != nil {
			fail(c, 500, e)
			return
		}
		maskConfig(&v)
		c.JSON(200, v)
	})
	admin.PUT("/config", s.saveConfig)
	admin.GET("/sources/status", func(c *gin.Context) {
		rows, err := s.engine.SourceStatuses()
		if err != nil {
			fail(c, 500, err)
			return
		}
		c.JSON(200, rows)
	})
	admin.POST("/sources/check", func(c *gin.Context) {
		if err := s.engine.CheckSources(s.ctx); err != nil {
			fail(c, 409, err)
			return
		}
		c.JSON(202, gin.H{"ok": true})
	})
	admin.POST("/vulnerabilities/refilter", func(c *gin.Context) {
		s.mu.Lock()
		defer s.mu.Unlock()
		cfg, err := s.store.Config()
		if err != nil {
			fail(c, 500, err)
			return
		}
		changed, err := s.store.SaveConfigAndRefilter(cfg)
		if err != nil {
			fail(c, 500, err)
			return
		}
		c.JSON(200, gin.H{"changed": changed})
	})
	admin.GET("/users", func(c *gin.Context) {
		v, e := s.store.Users()
		if e != nil {
			fail(c, 500, e)
			return
		}
		c.JSON(200, v)
	})
	admin.POST("/users", s.createUser)
	admin.PATCH("/users/:id", s.updateUser)
	r.GET("/api/vulnerabilities", s.reportAccess, func(c *gin.Context) {
		v, e := s.store.Vulnerabilities()
		if e != nil {
			fail(c, 500, e)
			return
		}
		c.JSON(200, v)
	})
	admin.POST("/vulnerabilities/:id/solution", s.generateSolution)
	admin.PATCH("/vulnerabilities/:id", func(c *gin.Context) {
		var body struct {
			Selected *bool `json:"selected"`
		}
		if !bind(c, &body) {
			return
		}
		if body.Selected == nil {
			fail(c, 400, "必须指定筛选状态")
			return
		}
		var v Vulnerability
		if err := s.store.get("vulnerability", c.Param("id"), &v); err != nil {
			fail(c, 404, "漏洞不存在")
			return
		}
		v.Selected = *body.Selected
		v.FilterReason = "手动排除"
		if v.Selected {
			v.FilterReason = "手动通过"
		}
		if err := s.store.put("vulnerability", v.ID, v); err != nil {
			fail(c, 500, err)
			return
		}
		c.JSON(200, v)
	})
	admin.POST("/reports/:id/cancel", func(c *gin.Context) {
		if err := s.engine.CancelReport(c.Param("id")); err != nil {
			fail(c, 409, err)
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})
	admin.GET("/deliveries", func(c *gin.Context) {
		v, e := s.store.Deliveries()
		if e != nil {
			fail(c, 500, e)
			return
		}
		c.JSON(200, v)
	})
	admin.POST("/collect", func(c *gin.Context) {
		job, e := s.engine.StartCollection(s.ctx)
		if e != nil {
			fail(c, 409, e)
			return
		}
		c.JSON(202, job)
	})
	admin.POST("/reports", func(c *gin.Context) {
		var b struct {
			Kind  string `json:"kind"`
			Start string `json:"start_date"`
			End   string `json:"end_date"`
		}
		if !bind(c, &b) {
			return
		}
		task := s.ctx
		if b.Kind == "custom" {
			var err error
			task, err = withReportPeriod(task, b.Start, b.End)
			if err != nil {
				fail(c, 400, err)
				return
			}
		}
		v, e := s.engine.StartReport(task, b.Kind, false)
		if e != nil {
			fail(c, 502, e)
			return
		}
		c.JSON(201, v)
	})
	admin.GET("/collection-jobs", func(c *gin.Context) {
		items := []CollectionJob{}
		if err := s.store.all("collection_job", &items); err != nil {
			fail(c, 500, err)
			return
		}
		for i := range items {
			items[i].Error = sourceErrorMessage(items[i].Error)
		}
		c.JSON(200, items)
	})
	admin.GET("/reports/:id/events", func(c *gin.Context) {
		items := []ReportEvent{}
		if err := s.store.all("report_event", &items); err != nil {
			fail(c, 500, err)
			return
		}
		out := []ReportEvent{}
		for i := len(items) - 1; i >= 0; i-- {
			if items[i].ReportID == c.Param("id") {
				out = append(out, items[i])
			}
		}
		c.JSON(200, out)
	})
	admin.DELETE("/reports/:id", func(c *gin.Context) {
		if err := s.engine.DeleteReport(c.Param("id")); err != nil {
			fail(c, 409, err)
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})
	admin.POST("/reports/:id/send", func(c *gin.Context) {
		if e := s.engine.SendReport(c.Request.Context(), c.Param("id")); e != nil {
			fail(c, 502, e)
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})
	admin.POST("/notifications/test", func(c *gin.Context) {
		var n Notification
		if !bind(c, &n) {
			return
		}
		cfg, e := s.store.Config()
		if e != nil {
			fail(c, 500, e)
			return
		}
		for _, old := range cfg.Notifications {
			if old.ID == n.ID {
				for k, v := range n.Settings {
					if v == "********" {
						n.Settings[k] = old.Settings[k]
					}
				}
			}
		}
		if e := s.engine.TestNotification(c.Request.Context(), n); e != nil {
			fail(c, 502, e)
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			fail(c, 404, "接口不存在")
			return
		}
		if c.Request.Method != "GET" {
			fail(c, 405, "不支持此方法")
			return
		}
		p := filepath.Join(s.assets, filepath.Clean("/"+c.Request.URL.Path))
		if info, e := os.Stat(p); e == nil && !info.IsDir() {
			c.File(p)
			return
		}
		index := filepath.Join(s.assets, "index.html")
		if _, e := os.Stat(index); e != nil {
			fail(c, 503, "前端尚未构建，请在frontend目录运行npm ci及npm run build")
			return
		}
		c.File(index)
	})
	return r
}
func (s *Server) status(c *gin.Context) {
	s.mu.RLock()
	st := s.store
	s.mu.RUnlock()
	v := DefaultConfig()
	providers := []string{}
	if st != nil {
		var e error
		v, e = st.Config()
		if e != nil {
			fail(c, 500, e)
			return
		}
	}
	if v.Auth.LDAP.Enabled {
		providers = append(providers, "ldap")
	}
	if v.Auth.OIDC.Enabled {
		providers = append(providers, "oidc")
	}
	if v.Auth.Feishu.Enabled {
		providers = append(providers, "feishu")
	}
	if v.Auth.Dingtalk.Enabled {
		providers = append(providers, "dingtalk")
	}
	c.JSON(200, gin.H{"initialized": st != nil, "branding": v.Branding, "providers": providers, "report_access": v.Auth.ReportAccess})
}
func (s *Server) setup(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		fail(c, 409, "已经初始化")
		return
	}
	var b struct{ Database, DSN, Password, Title string }
	if !bind(c, &b) {
		return
	}
	if len(b.Password) < 9 || len(b.Password) > 72 {
		fail(c, 400, "密码须为9至72字节")
		return
	}
	if e := os.MkdirAll(s.dir, 0700); e != nil {
		fail(c, 500, e)
		return
	}
	if b.Database == "sqlite" && b.DSN == "" {
		b.DSN = filepath.Join(s.dir, "watchvuln.db")
	}
	st, e := OpenStore(b.Database, b.DSN)
	if e != nil {
		fail(c, 400, e)
		return
	}
	cfg := DefaultConfig()
	if b.Title != "" {
		cfg.Branding.Title = b.Title
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(b.Password), bcrypt.DefaultCost)
	if e != nil {
		st.db.Close()
		fail(c, 500, e)
		return
	}
	u := User{ID: ID(), Username: "admin", DisplayName: "管理员", Provider: "local", Role: "admin", PasswordHash: string(hash), CreatedAt: time.Now().UTC()}
	existing, e := st.Users()
	if e != nil || len(existing) > 0 {
		st.db.Close()
		fail(c, 409, "目标数据库已含用户，禁止覆盖初始化")
		return
	}
	if e = st.SaveConfig(cfg); e == nil {
		e = st.SaveUser(u)
	}
	if e == nil {
		e = saveBootstrap(s.dir, bootstrap{b.Database, b.DSN})
	}
	if e != nil {
		st.db.Close()
		fail(c, 500, e)
		return
	}
	s.store = st
	s.startEngine()
	c.JSON(201, gin.H{"ok": true})
}
func (s *Server) allowLogin(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	a := []time.Time{}
	for _, t := range s.attempts[ip] {
		if now.Sub(t) < 9*time.Minute {
			a = append(a, t)
		}
	}
	if len(a) >= 20 {
		return false
	}
	s.attempts[ip] = append(a, now)
	return true
}
func (s *Server) login(c *gin.Context) {
	s.mu.RLock()
	st := s.store
	s.mu.RUnlock()
	if st == nil {
		fail(c, 409, "尚未初始化")
		return
	}
	if !s.allowLogin(c.ClientIP()) {
		fail(c, 429, "尝试次数过多，请稍后重试")
		return
	}
	var b struct{ Username, Password, Provider string }
	if !bind(c, &b) {
		return
	}
	var u User
	var e error
	if b.Provider == "ldap" {
		u, e = s.ldapLogin(b.Username, b.Password)
	} else if b.Provider == "" || b.Provider == "local" {
		u, e = st.FindUser("local", b.Username)
		if e == nil {
			e = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(b.Password))
		}
	} else {
		e = errors.New("不支持此登录方式")
	}
	if e != nil || u.Disabled {
		fail(c, 401, "用户名或密码错误，或账户已禁用")
		return
	}
	s.loginUser(c, u)
	c.JSON(200, u)
}
func (s *Server) password(c *gin.Context) {
	u := c.MustGet("user").(User)
	if u.Provider != "local" {
		fail(c, 400, "外部账户请在身份提供商修改密码")
		return
	}
	var b struct {
		OldPassword string `json:"old_password"`
		Password    string `json:"password"`
	}
	if !bind(c, &b) {
		return
	}
	if len(b.Password) < 9 || len(b.Password) > 72 || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(b.OldPassword)) != nil {
		fail(c, 400, "原密码错误或新密码长度不符合要求")
		return
	}
	h, e := bcrypt.GenerateFromPassword([]byte(b.Password), bcrypt.DefaultCost)
	if e != nil {
		fail(c, 500, e)
		return
	}
	u.PasswordHash = string(h)
	if e = s.store.SaveUser(u); e != nil {
		fail(c, 500, e)
		return
	}
	s.mu.Lock()
	for k, v := range s.sessions {
		if v.UserID == u.ID {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
	s.loginUser(c, u)
	c.JSON(200, gin.H{"ok": true})
}
func (s *Server) createUser(c *gin.Context) {
	var b struct {
		Username, Password string
		DisplayName        string `json:"display_name"`
	}
	if !bind(c, &b) {
		return
	}
	if strings.TrimSpace(b.Username) == "" || len(b.Username) > 100 || len(b.Password) < 9 || len(b.Password) > 72 {
		fail(c, 400, "用户名不能为空，密码须为9至72字节")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, e := s.store.FindUser("local", b.Username)
	if e == nil {
		fail(c, 409, "用户已存在")
		return
	}
	if !errors.Is(e, sql.ErrNoRows) {
		fail(c, 500, e)
		return
	}
	h, e := bcrypt.GenerateFromPassword([]byte(b.Password), bcrypt.DefaultCost)
	if e != nil {
		fail(c, 500, e)
		return
	}
	u := User{ID: ID(), Username: b.Username, DisplayName: b.DisplayName, Provider: "local", Role: "user", PasswordHash: string(h), CreatedAt: time.Now().UTC()}
	if e = s.store.SaveUser(u); e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(201, u)
}
func (s *Server) updateUser(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, e := s.store.User(c.Param("id"))
	if e != nil {
		fail(c, 404, "用户不存在")
		return
	}
	var b struct {
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	if !bind(c, &b) {
		return
	}
	if b.Role != "admin" && b.Role != "user" {
		fail(c, 400, "角色无效")
		return
	}
	if u.Username == "admin" && u.Provider == "local" && (b.Role != "admin" || b.Disabled) {
		fail(c, 400, "内置admin不可降权或禁用")
		return
	}
	u.Role = b.Role
	u.Disabled = b.Disabled
	if e = s.store.SaveUser(u); e != nil {
		fail(c, 500, e)
		return
	}
	c.JSON(200, u)
}
func validURL(raw string, required bool) error {
	if raw == "" && !required {
		return nil
	}
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("无效HTTP地址: %s", raw)
	}
	return nil
}
func validateConfig(v Config) error {
	if strings.TrimSpace(v.Branding.Title) == "" {
		return errors.New("标题不能为空")
	}
	if v.Branding.Logo != "" && !strings.HasPrefix(v.Branding.Logo, "/") {
		if e := validURL(v.Branding.Logo, true); e != nil {
			return e
		}
	}
	if e := validURL(v.Branding.PublicURL, false); e != nil {
		return e
	}
	if v.Collector.WindowStart != "" || v.Collector.WindowEnd != "" {
		for _, value := range []string{v.Collector.WindowStart, v.Collector.WindowEnd} {
			parsed, err := time.Parse("15:04", value)
			if err != nil || parsed.Format("15:04") != value {
				return errors.New("采集时间请使用HH:mm格式，开始结束必须同时填写")
			}
		}
	}
	d, e := time.ParseDuration(v.Collector.Interval)
	if e != nil || d < time.Minute {
		return errors.New("采集间隔至少1分钟")
	}
	allowed := map[string]bool{"avd": true, "nox": true, "ti": true, "oscs": true, "threatbook": true, "seebug": true, "struts2": true, "kev": true, "venustech": true, "chaitin": true}
	for _, src := range v.Collector.Sources {
		if !allowed[src] {
			return fmt.Errorf("未知漏洞源 %s", src)
		}
	}
	if v.Collector.Enabled && len(v.Collector.Sources) == 0 {
		return errors.New("请至少选择一个采集源")
	}
	if v.Collector.Proxy != "" {
		p, e := url.Parse(v.Collector.Proxy)
		if e != nil || p.Host == "" || (p.Scheme != "http" && p.Scheme != "https" && p.Scheme != "socks5") {
			return errors.New("代理地址无效")
		}
	}
	for _, r := range v.Rules {
		if r.Kind != "black" && r.Kind != "white" {
			return errors.New("名单类型必须是black或white")
		}
		if r.Pattern == "" || len(r.Fields) == 0 {
			return errors.New("名单规则必须含匹配内容和字段")
		}
		for _, f := range r.Fields {
			if f != "title" && f != "tags" && f != "description" && f != "solution" {
				return errors.New("无效名单匹配字段")
			}
		}
		if r.Regex {
			if _, e := regexp.Compile(r.Pattern); e != nil {
				return e
			}
		}
	}
	if v.Auth.ReportAccess != "public" && v.Auth.ReportAccess != "authenticated" {
		return errors.New("报告访问权限无效")
	}
	if v.AI.Hour < 0 || v.AI.Hour > 23 || v.AI.Weekday < 0 || v.AI.Weekday > 6 || v.AI.MaxItems < 1 || v.AI.MaxItems > 500 {
		return errors.New("AI调度时间或max_items无效")
	}
	if v.AI.TimeoutSeconds != 0 && (v.AI.TimeoutSeconds < 30 || v.AI.TimeoutSeconds > 1800) {
		return errors.New("单次AI请求超时须为30至1800秒")
	}
	if v.DeliveryRetentionDays < 0 || v.DeliveryRetentionDays > 3650 {
		return errors.New("通知记录保留天数必须为0至3650")
	}
	if v.AI.RetentionDays < 0 || v.AI.RetentionDays > 3650 {
		return errors.New("报告保留天数必须为0至3650，0表示永久保留")
	}
	if v.AI.RetryCount < 0 || v.AI.RetryCount > 20 {
		return errors.New("AI失败重试次数必须为0至20")
	}
	if _, e := time.LoadLocation(v.AI.Timezone); e != nil {
		return e
	}
	if v.AI.Enabled {
		if e := validURL(v.AI.BaseURL, true); e != nil {
			return e
		}
		if v.AI.APIKey == "" || v.AI.Model == "" {
			return errors.New("AI需要API Key和模型")
		}
	}
	if v.Auth.OIDC.Enabled {
		if e := validURL(v.Auth.OIDC.Issuer, true); e != nil {
			return e
		}
	}
	for _, o := range []OAuthConfig{v.Auth.OIDC, v.Auth.Feishu, v.Auth.Dingtalk} {
		if o.Enabled && (o.ClientID == "" || o.ClientSecret == "" || v.Branding.PublicURL == "") {
			return errors.New("外部登录须配置客户端ID/密钥及公开访问URL")
		}
	}
	if v.Auth.LDAP.Enabled {
		u, e := url.Parse(v.Auth.LDAP.URL)
		if e != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
			return errors.New("LDAP URL无效")
		}
		if u.Scheme == "ldap" && !v.Auth.LDAP.StartTLS {
			return errors.New("LDAP必须启用StartTLS或使用ldaps")
		}
		if !strings.Contains(v.Auth.LDAP.UserFilter, "{username}") || v.Auth.LDAP.BaseDN == "" {
			return errors.New("LDAP需要base_dn及含{username}的过滤器")
		}
	}
	for _, n := range v.Notifications {
		if e := validateNotification(n); e != nil {
			return e
		}
	}
	return nil
}
func secretKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "secret") || strings.Contains(k, "token") || strings.Contains(k, "password") || k == "key" || k == "apikey" || k == "url" || k == "webhook_url"
}
func maskConfig(v *Config) {
	if v.AI.APIKey != "" {
		v.AI.APIKey = "********"
	}
	if v.Auth.LDAP.BindPassword != "" {
		v.Auth.LDAP.BindPassword = "********"
	}
	for _, p := range []*OAuthConfig{&v.Auth.OIDC, &v.Auth.Feishu, &v.Auth.Dingtalk} {
		if p.ClientSecret != "" {
			p.ClientSecret = "********"
		}
	}
	for i := range v.Notifications {
		for k, value := range v.Notifications[i].Settings {
			if secretKey(k) && value != "" {
				v.Notifications[i].Settings[k] = "********"
			}
		}
	}
}
func (s *Server) saveConfig(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v Config
	if !bind(c, &v) {
		return
	}
	v.Branding.Title = "WatchVuln AI"
	v.Branding.Logo = "/logo.svg"
	old, e := s.store.Config()
	if e != nil {
		fail(c, 500, e)
		return
	}
	if v.AI.APIKey == "********" {
		v.AI.APIKey = old.AI.APIKey
	}
	if v.Auth.LDAP.BindPassword == "********" {
		v.Auth.LDAP.BindPassword = old.Auth.LDAP.BindPassword
	}
	newP := []*OAuthConfig{&v.Auth.OIDC, &v.Auth.Feishu, &v.Auth.Dingtalk}
	oldP := []OAuthConfig{old.Auth.OIDC, old.Auth.Feishu, old.Auth.Dingtalk}
	for i, p := range newP {
		if p.ClientSecret == "********" {
			p.ClientSecret = oldP[i].ClientSecret
		}
	}
	for i := range v.Notifications {
		if v.Notifications[i].ID == "" {
			v.Notifications[i].ID = ID()
		}
		for _, n := range old.Notifications {
			if n.ID == v.Notifications[i].ID {
				for k, value := range v.Notifications[i].Settings {
					if value == "********" {
						v.Notifications[i].Settings[k] = n.Settings[k]
					}
				}
			}
		}
	}
	for i := range v.Rules {
		if v.Rules[i].ID == "" {
			v.Rules[i].ID = ID()
		}
	}
	if e = validateConfig(v); e != nil {
		fail(c, 400, e)
		return
	}
	if c.Query("filter_history") == "true" {
		_, e = s.store.SaveConfigAndRefilter(v)
	} else {
		e = s.store.SaveConfig(v)
	}
	if e != nil {
		fail(c, 500, e)
		return
	}
	maskConfig(&v)
	c.JSON(200, v)
}
