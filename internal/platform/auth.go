package platform

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) externalUser(provider, subject, name string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, e := s.store.FindUser(provider, subject)
	if errors.Is(e, sql.ErrNoRows) {
		u = User{ID: ID(), Username: subject, DisplayName: name, Provider: provider, Role: "user", CreatedAt: time.Now().UTC()}
		e = s.store.SaveUser(u)
	}
	if e != nil {
		return User{}, e
	}
	if u.Disabled {
		return User{}, errors.New("账户已被禁用")
	}
	return u, nil
}
func (s *Server) ldapLogin(username, password string) (User, error) {
	if username == "" || password == "" {
		return User{}, errors.New("凭据不能为空")
	}
	cfg, e := s.store.Config()
	if e != nil {
		return User{}, e
	}
	a := cfg.Auth.LDAP
	if !a.Enabled {
		return User{}, errors.New("LDAP未开启")
	}
	conn, e := ldap.DialURL(a.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if e != nil {
		return User{}, e
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	if a.StartTLS {
		u, _ := url.Parse(a.URL)
		if e = conn.StartTLS(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}); e != nil {
			return User{}, e
		}
	}
	if a.BindDN != "" {
		if e = conn.Bind(a.BindDN, a.BindPassword); e != nil {
			return User{}, e
		}
	}
	filter := strings.ReplaceAll(a.UserFilter, "{username}", ldap.EscapeFilter(username))
	res, e := conn.Search(ldap.NewSearchRequest(a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, filter, []string{"displayName", "cn", "entryUUID", "objectGUID"}, nil))
	if e != nil {
		return User{}, e
	}
	if len(res.Entries) != 1 {
		return User{}, errors.New("LDAP用户不唯一或不存在")
	}
	entry := res.Entries[0]
	if e = conn.Bind(entry.DN, password); e != nil {
		return User{}, e
	}
	name := entry.GetAttributeValue("displayName")
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	subject := entry.GetAttributeValue("entryUUID")
	if subject == "" {
		subject = entry.DN
	}
	return s.externalUser("ldap", subject, name)
}
func (s *Server) oauthConfig(ctx context.Context, provider string) (*oauth2.Config, *oidc.Provider, error) {
	s.mu.RLock()
	st := s.store
	s.mu.RUnlock()
	if st == nil {
		return nil, nil, errors.New("尚未初始化")
	}
	cfg, e := st.Config()
	if e != nil {
		return nil, nil, e
	}
	var a OAuthConfig
	var ep oauth2.Endpoint
	scopes := []string{}
	var op *oidc.Provider
	switch provider {
	case "oidc":
		a = cfg.Auth.OIDC
		if !a.Enabled {
			return nil, nil, errors.New("OIDC未开启")
		}
		op, e = oidc.NewProvider(ctx, a.Issuer)
		if e != nil {
			return nil, nil, e
		}
		ep = op.Endpoint()
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
		if a.Scopes != "" {
			scopes = append(scopes, strings.Fields(a.Scopes)...)
		}
	case "feishu":
		a = cfg.Auth.Feishu
		ep = oauth2.Endpoint{AuthURL: "https://accounts.feishu.cn/open-apis/authen/v1/authorize", TokenURL: "https://open.feishu.cn/open-apis/authen/v2/oauth/token", AuthStyle: oauth2.AuthStyleInParams}
		scopes = []string{"contact:user.base:readonly"}
	case "dingtalk":
		a = cfg.Auth.Dingtalk
		ep = oauth2.Endpoint{AuthURL: "https://login.dingtalk.com/oauth2/auth"}
		scopes = []string{"openid"}
	default:
		return nil, nil, errors.New("未知身份提供商")
	}
	if !a.Enabled {
		return nil, nil, errors.New("此登录方式未开启")
	}
	if cfg.Branding.PublicURL == "" {
		return nil, nil, errors.New("未配置公开访问地址")
	}
	return &oauth2.Config{ClientID: a.ClientID, ClientSecret: a.ClientSecret, RedirectURL: strings.TrimRight(cfg.Branding.PublicURL, "/") + "/api/oauth/" + provider + "/callback", Endpoint: ep, Scopes: scopes}, op, nil
}
func oauthContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	return context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: 20 * time.Second}), cancel
}
func (s *Server) oauthStart(c *gin.Context) {
	ctx, cancel := oauthContext(c.Request.Context())
	defer cancel()
	provider := c.Param("provider")
	cfg, _, e := s.oauthConfig(ctx, provider)
	if e != nil {
		fail(c, 400, e)
		return
	}
	state, nonce := randomToken(), randomToken()
	s.mu.Lock()
	for k, v := range s.states {
		if time.Now().After(v.Expires) {
			delete(s.states, k)
		}
	}
	s.states[tokenKey(state)] = oauthState{provider, nonce, time.Now().Add(5 * time.Minute)}
	s.mu.Unlock()
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("watchvuln_oauth", state, 300, "/api/oauth", "", c.Request.TLS != nil, true)
	options := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
	if provider == "dingtalk" {
		options = append(options, oauth2.SetAuthURLParam("prompt", "consent"))
	}
	c.Redirect(302, cfg.AuthCodeURL(state, options...))
}
func (s *Server) oauthCallback(c *gin.Context) {
	state := c.Query("state")
	cookie, _ := c.Cookie("watchvuln_oauth")
	if state == "" || state != cookie {
		fail(c, 400, "登录state校验失败")
		return
	}
	s.mu.Lock()
	v, ok := s.states[tokenKey(state)]
	delete(s.states, tokenKey(state))
	s.mu.Unlock()
	c.SetCookie("watchvuln_oauth", "", -1, "/api/oauth", "", false, true)
	if !ok || v.Provider != c.Param("provider") || time.Now().After(v.Expires) {
		fail(c, 400, "登录请求已过期")
		return
	}
	code := c.Query("code")
	if code == "" {
		code = c.Query("authCode")
	}
	if code == "" {
		fail(c, 400, "未收到授权码")
		return
	}
	ctx, cancel := oauthContext(c.Request.Context())
	defer cancel()
	cfg, op, e := s.oauthConfig(ctx, v.Provider)
	if e != nil {
		fail(c, 502, e)
		return
	}
	var subject, name string
	if v.Provider == "dingtalk" {
		var tok struct {
			AccessToken string `json:"accessToken"`
		}
		e = jsonRequest(ctx, "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", map[string]any{"clientId": cfg.ClientID, "clientSecret": cfg.ClientSecret, "code": code, "grantType": "authorization_code"}, nil, &tok)
		if e == nil && tok.AccessToken == "" {
			e = errors.New("钉钉未返回accessToken")
		}
		if e == nil {
			var info struct {
				UnionID string `json:"unionId"`
				Nick    string `json:"nick"`
			}
			e = getJSON(ctx, "https://api.dingtalk.com/v1.0/contact/users/me", map[string]string{"x-acs-dingtalk-access-token": tok.AccessToken}, &info)
			subject, name = info.UnionID, info.Nick
		}
	} else {
		var token *oauth2.Token
		token, e = cfg.Exchange(ctx, code)
		if e == nil && v.Provider == "oidc" {
			raw, _ := token.Extra("id_token").(string)
			var id *oidc.IDToken
			id, e = op.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
			if e == nil {
				if id.Nonce != v.Nonce {
					e = errors.New("OIDC nonce不匹配")
				} else {
					var claims struct {
						Name      string `json:"name"`
						Preferred string `json:"preferred_username"`
					}
					e = id.Claims(&claims)
					subject, name = id.Subject, claims.Name
					if name == "" {
						name = claims.Preferred
					}
				}
			}
		} else if e == nil {
			var info struct {
				Code int    `json:"code"`
				Msg  string `json:"msg"`
				Data struct {
					OpenID string `json:"open_id"`
					Name   string `json:"name"`
				} `json:"data"`
			}
			e = getJSON(ctx, "https://open.feishu.cn/open-apis/authen/v1/user_info", map[string]string{"Authorization": "Bearer " + token.AccessToken}, &info)
			if e == nil && info.Code != 0 {
				e = fmt.Errorf("飞书登录失败: %s", info.Msg)
			}
			subject, name = info.Data.OpenID, info.Data.Name
		}
	}
	if e != nil || subject == "" {
		logMsg := "外部登录失败"
		if e != nil {
			logMsg = e.Error()
		}
		fail(c, 502, logMsg)
		return
	}
	u, e := s.externalUser(v.Provider, subject, name)
	if e != nil {
		fail(c, 403, e)
		return
	}
	s.loginUser(c, u)
	c.Redirect(302, "/")
}
func jsonRequest(ctx context.Context, endpoint string, body any, headers map[string]string, out any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doJSON(req, out)
}
func getJSON(ctx context.Context, endpoint string, headers map[string]string, out any) error {
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return e
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doJSON(req, out)
}
func doJSON(req *http.Request, out any) error {
	res, e := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if e != nil {
		return e
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("远端服务HTTP %d", res.StatusCode)
	}
	if out == nil || (res.StatusCode == http.StatusNoContent && len(b) == 0) {
		return nil
	}
	return json.Unmarshal(b, out)
}
