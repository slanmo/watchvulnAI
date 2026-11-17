package platform

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

type PushJob struct {
	ID              string    `json:"id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	Title           string    `json:"title"`
	Status          string    `json:"status"`
	Error           string    `json:"error,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
}

func (e *Engine) StartPush(ctx context.Context, id string) (PushJob, error) {
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	var v Vulnerability
	if err := e.store.get("vulnerability", id, &v); err != nil {
		return PushJob{}, errors.New("漏洞不存在")
	}
	cfg, err := e.store.Config()
	if err != nil {
		return PushJob{}, err
	}
	enabled := false
	for _, n := range cfg.Notifications {
		enabled = enabled || n.Enabled
	}
	if !enabled {
		return PushJob{}, errors.New("没有已启用的通知渠道")
	}
	rows := []PushJob{}
	if err = e.store.all("push_job", &rows); err != nil {
		return PushJob{}, err
	}
	for _, j := range rows {
		if j.VulnerabilityID == id && j.Status == "running" {
			return PushJob{}, errors.New("该漏洞正在推送")
		}
	}
	j := PushJob{ID: ID(), VulnerabilityID: id, Title: v.Title, Status: "running", CreatedAt: time.Now().UTC()}
	if err = e.store.put("push_job", j.ID, j); err != nil {
		return j, err
	}
	go func() {
		err := e.pushVulnerability(ctx, cfg, v)
		j.Status = "ready"
		if err != nil {
			j.Status = "failed"
			j.Error = err.Error()
		}
		j.FinishedAt = time.Now().UTC()
		_ = e.store.put("push_job", j.ID, j)
	}()
	return j, nil
}
func (e *Engine) pushVulnerability(ctx context.Context, cfg Config, v Vulnerability) error {
	var err error
	if v.Selected && cfg.Collector.AISolution && v.AIAnalysis == nil {
		copy := v
		copy.Solution = ""
		v, err = e.enrichBeforePush(ctx, cfg, copy)
		if err != nil {
			return err
		}
	} else {
		if err = e.store.get("vulnerability", v.ID, &v); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	link := v.URL
	if cfg.Branding.PublicURL != "" {
		link = strings.TrimRight(cfg.Branding.PublicURL, "/") + "/vulnerabilities/" + url.PathEscape(v.ID)
	}
	return e.notifyAll(context.WithValue(ctx, vulnerabilityContextKey{}, &v), cfg, v.Title, vulnerabilityMarkdown(v), link, nil)
}
