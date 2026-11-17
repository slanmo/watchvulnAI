package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type SourceHealth struct {
	Source     string    `json:"source"`
	Status     string    `json:"status"`
	Count      int       `json:"count"`
	Error      string    `json:"error,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	CheckedAt  time.Time `json:"checked_at"`
}

func (e *Engine) SourceStatuses() ([]SourceHealth, error) {
	out := []SourceHealth{}
	err := e.store.all("source_health", &out)
	for i := range out {
		out[i].Error = sourceErrorMessage(out[i].Error)
	}
	return out, err
}
func (e *Engine) CheckSources(ctx context.Context) error {
	e.jobMu.Lock()
	if e.healthRunning {
		e.jobMu.Unlock()
		return errors.New("源状态检查正在运行")
	}
	e.healthRunning = true
	e.jobMu.Unlock()
	cfg, err := e.store.Config()
	if err != nil {
		e.jobMu.Lock()
		e.healthRunning = false
		e.jobMu.Unlock()
		return err
	}
	sources := []string{}
	seen := map[string]bool{}
	for _, src := range cfg.Collector.Sources {
		if src == "ti" {
			src = "nox"
		}
		if !seen[src] {
			seen[src] = true
			sources = append(sources, src)
		}
	}
	for _, src := range sources {
		if err = e.store.put("source_health", src, SourceHealth{Source: src, Status: "checking", CheckedAt: time.Now().UTC()}); err != nil {
			e.jobMu.Lock()
			e.healthRunning = false
			e.jobMu.Unlock()
			return err
		}
	}
	go func() {
		defer func() { e.jobMu.Lock(); e.healthRunning = false; e.jobMu.Unlock() }()
		for _, src := range sources {
			start := time.Now()
			v := SourceHealth{Source: src, Status: "healthy", CheckedAt: start.UTC()}
			result, err := probeSource(ctx, cfg.Collector, src)
			v.DurationMS = time.Since(start).Milliseconds()
			v.Count = len(result.Vulns)
			if err != nil {
				v.Status = "failed"
				v.Error = err.Error()
			} else if result.Error != "" {
				v.Status = "failed"
				v.Error = result.Error
			} else if v.Count == 0 {
				v.Status = "empty"
			}
			_ = e.store.put("source_health", src, v)
		}
	}()
	return nil
}
func probeSource(ctx context.Context, cfg CollectorConfig, src string) (collected, error) {
	var result collected
	exe, err := os.Executable()
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--collector-worker", src)
	env := []string{}
	for _, v := range os.Environ() {
		k := strings.ToUpper(strings.SplitN(v, "=", 2)[0])
		if k != "HTTP_PROXY" && k != "HTTPS_PROXY" && k != "ALL_PROXY" && k != "GO_SKIP_TLS_CHECK" && k != "WATCHVULN_GITHUB_SEARCH" {
			env = append(env, v)
		}
	}
	if cfg.Proxy != "" {
		env = append(env, "HTTP_PROXY="+cfg.Proxy, "HTTPS_PROXY="+cfg.Proxy, "ALL_PROXY="+cfg.Proxy)
	}
	if cfg.SkipTLSVerify {
		env = append(env, "GO_SKIP_TLS_CHECK=1")
	}
	env = append(env, "WATCHVULN_PROBE=1")
	cmd.Env = env
	raw, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fmt.Errorf("采集器检查失败: %w", err)
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}
