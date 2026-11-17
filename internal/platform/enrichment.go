package platform

import (
	"context"
	"errors"
	"strings"
	"time"
)

func (e *Engine) enrichBeforePush(ctx context.Context, cfg Config, v Vulnerability) (Vulnerability, error) {
	if !cfg.Collector.AISolution || v.AIAnalysis != nil || strings.TrimSpace(v.Solution) != "" {
		return v, nil
	}
	job := SolutionJob{ID: ID(), VulnerabilityID: v.ID, Status: "running", CreatedAt: time.Now().UTC()}
	if err := e.store.put("solution_job", job.ID, job); err != nil {
		return v, err
	}
	var err error
	if !cfg.AI.Enabled {
		err = errors.New("AI模型未启用，跳过漏洞分析补充")
	} else {
		err = e.buildAnalysis(ctx, cfg, v)
	}
	job.Status = "ready"
	if err != nil {
		job.Status = "failed"
		job.Error = "AI补充失败，使用原始内容推送: " + err.Error()
	}
	job.FinishedAt = time.Now().UTC()
	if saveErr := e.store.put("solution_job", job.ID, job); saveErr != nil {
		return v, saveErr
	}
	if ctx.Err() != nil {
		return v, ctx.Err()
	}
	var latest Vulnerability
	if readErr := e.store.get("vulnerability", v.ID, &latest); readErr != nil {
		return v, readErr
	}
	return latest, nil
}
