package platform

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var notificationFields = map[string][]string{"dingding": {"access_token"}, "lark": {"access_token"}, "wechatwork": {"key"}, "webhook": {"url"}, "slack": {"webhook_url"}, "telegram": {"bot_token", "chat_ids"}, "bark": {"url"}, "serverchan": {"key"}, "pushplus": {"token"}, "wpush": {"apikey"}, "lanxin": {"domain", "access_token", "sign_secret"}}

func validateNotification(n Notification) error {
	fields, ok := notificationFields[n.Type]
	if !ok {
		return fmt.Errorf("不支持的通知类型 %s", n.Type)
	}
	if n.Enabled {
		for _, k := range fields {
			if n.Settings[k] == "" {
				return fmt.Errorf("通知 %s 缺少 %s", n.Name, k)
			}
		}
	}
	return nil
}
func signed(secret, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func (e *Engine) TestNotification(ctx context.Context, n Notification) error {
	n.Enabled = true
	if err := validateNotification(n); err != nil {
		return err
	}
	return sendNotification(ctx, n, "WatchVuln 测试通知", "通知服务已成功连接。", "", nil)
}
func (e *Engine) notifyAll(ctx context.Context, cfg Config, title, text, link string, r *Report) error {
	errs := []string{}
	for _, n := range cfg.Notifications {
		if !n.Enabled {
			continue
		}
		d := Delivery{ID: ID(), ChannelID: n.ID, CreatedAt: time.Now().UTC(), Status: "pending", Title: title, Text: text, Link: link}
		d.Vulnerability, _ = ctx.Value(vulnerabilityContextKey{}).(*Vulnerability)
		if r != nil {
			d.ReportID = r.ID
		}
		if err := e.store.PutDelivery(d); err != nil {
			return err
		}
		err := sendNotification(ctx, n, title, text, link, r)
		d.Attempts = 1
		d.Status = "sent"
		if r != nil {
			d.ReportID = r.ID
		}
		if err != nil {
			d.Status = "failed"
			d.NextAttempt = time.Now().Add(time.Minute)
			d.Error = err.Error()
			errs = append(errs, n.Name+": "+err.Error())
		}
		if er := e.store.PutDelivery(d); er != nil {
			errs = append(errs, "保存投递记录: "+er.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
func (e *Engine) SendReport(ctx context.Context, id string) error {
	r, err := e.store.Report(id)
	if err != nil {
		return err
	}
	if r.Status != "ready" {
		return errors.New("报告尚未生成成功")
	}
	cfg, err := e.store.Config()
	if err != nil {
		return err
	}
	link := strings.TrimRight(cfg.Branding.PublicURL, "/") + "/api/reports/" + url.PathEscape(id) + "/html"
	enabled := false
	for _, n := range cfg.Notifications {
		enabled = enabled || n.Enabled
	}
	if !enabled {
		return errors.New("没有已启用的通知渠道")
	}
	return e.notifyAll(ctx, cfg, r.Title, r.Summary, link, &r)
}
func sendNotification(ctx context.Context, n Notification, title, text, link string, r *Report) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	a := n.Settings
	markdown := text
	if link != "" {
		markdown += "\n\n[查看完整内容](" + link + ")"
	}
	var endpoint string
	var body any
	var codeKey string
	expected := float64(0)
	switch n.Type {
	case "dingding":
		endpoint = "https://oapi.dingtalk.com/robot/send?access_token=" + url.QueryEscape(a["access_token"])
		if a["sign_secret"] != "" {
			ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
			endpoint += "&timestamp=" + ts + "&sign=" + url.QueryEscape(signed(a["sign_secret"], ts+"\n"+a["sign_secret"]))
		}
		_, card := notificationCards(title, text, link, r)
		if v, ok := ctx.Value(vulnerabilityContextKey{}).(*Vulnerability); ok {
			_, card = vulnerabilityCards(*v, link)
		}
		body = card
		codeKey = "errcode"
	case "lark":
		endpoint = a["access_token"]
		if !strings.HasPrefix(endpoint, "https://") {
			endpoint = "https://open.feishu.cn/open-apis/bot/v2/hook/" + url.PathEscape(endpoint)
		}
		payload := map[string]any{}
		card, _ := notificationCards(title, text, link, r)
		if v, ok := ctx.Value(vulnerabilityContextKey{}).(*Vulnerability); ok {
			card, _ = vulnerabilityCards(*v, link)
		}
		payload["msg_type"] = "interactive"
		payload["card"] = card
		if a["sign_secret"] != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			payload["timestamp"] = ts
			payload["sign"] = signed(ts+"\n"+a["sign_secret"], "")
		}
		body = payload
		codeKey = "code"
	case "lanxin":
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		endpoint = strings.TrimRight(a["domain"], "/") + "/v1/bot/hook/messages/create?hook_token=" + url.QueryEscape(a["access_token"])
		body = map[string]any{"timestamp": ts, "sign": signed(ts+"@"+a["sign_secret"], ""), "msgType": "text", "msgData": map[string]any{"text": map[string]string{"content": title + "\n" + text + "\n" + link}}}
		codeKey = "errCode"
	case "wechatwork":
		endpoint = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + url.QueryEscape(a["key"])
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": "### " + title + "\n" + markdown}}
		codeKey = "errcode"
	case "webhook":
		endpoint = a["url"]
		body = map[string]any{"title": title, "content": text, "url": link, "report": r}
	case "slack":
		endpoint = a["webhook_url"]
		body = map[string]any{"text": title + "\n" + text + "\n" + link}
		if a["channel"] != "" {
			body.(map[string]any)["channel"] = a["channel"]
		}
		return postSlack(ctx, endpoint, body)
	case "telegram":
		errs := []string{}
		for _, id := range strings.Split(a["chat_ids"], ",") {
			for _, part := range messageChunks(title+"\n"+text+"\n"+link, 1900) {
				var resp map[string]any
				err := jsonRequest(ctx, "https://api.telegram.org/bot"+a["bot_token"]+"/sendMessage", map[string]any{"chat_id": strings.TrimSpace(id), "text": part}, nil, &resp)
				if err == nil && resp["ok"] != true {
					err = errors.New("Telegram业务响应失败")
				}
				if err != nil {
					errs = append(errs, err.Error())
					break
				}
			}
		}
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	case "bark":
		endpoint = a["url"]
		body = map[string]any{"title": title, "body": text, "url": link}
		codeKey = "code"
		expected = 200
	case "serverchan":
		endpoint = "https://sctapi.ftqq.com/" + url.PathEscape(a["key"]) + ".send"
		body = map[string]any{"title": title, "desp": markdown}
		codeKey = "code"
	case "pushplus":
		endpoint = "https://www.pushplus.plus/send"
		body = map[string]any{"token": a["token"], "title": title, "content": markdown, "template": "markdown"}
		codeKey = "code"
		expected = 200
	case "wpush":
		endpoint = "https://api.wpush.cn/api/v1/send"
		body = map[string]any{"apikey": a["apikey"], "title": title, "content": markdown, "channel": a["channel"], "topic_code": a["topic_code"]}
		codeKey = "code"
		expected = 0
	default:
		return errors.New("不支持的通知渠道")
	}
	if err := validURL(endpoint, true); err != nil {
		return err
	}
	var response map[string]any
	if err := jsonRequest(ctx, endpoint, body, nil, &response); err != nil {
		return err
	}
	if n.Type == "webhook" {
		if ok, exists := response["ok"]; exists && ok != true {
			return errors.New("Webhook业务响应ok不是true")
		}
		if code, exists := response["code"]; exists && code != float64(0) && code != float64(200) {
			return fmt.Errorf("Webhook业务响应失败code=%v", code)
		}
	}
	if codeKey != "" {
		code, ok := response[codeKey].(float64)
		if !ok || code != expected {
			return fmt.Errorf("通知服务业务响应失败（%s=%v）", codeKey, response[codeKey])
		}
	}
	return nil
}
