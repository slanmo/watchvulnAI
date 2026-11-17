package platform

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type baselineContextKey struct{}

func (e *Engine) needsBaseline() (bool, error) {
	var marker struct {
		Done bool `json:"done"`
	}
	err := e.store.get("state", "baseline", &marker)
	if err == nil {
		return !marker.Done, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	rows, err := e.store.Vulnerabilities()
	if err != nil {
		return false, err
	}
	if len(rows) > 0 {
		return false, e.store.put("state", "baseline", map[string]any{"done": true, "existing": true})
	}
	return true, nil
}
func (e *Engine) BootstrapCollection(ctx context.Context) error {
	needed, err := e.needsBaseline()
	if err != nil || !needed {
		return err
	}
	_, err = e.StartCollection(ctx)
	return err
}
func (e *Engine) finishBaseline(ctx context.Context, cfg Config, collectionErr error) error {
	rows, err := e.store.Vulnerabilities()
	if err != nil {
		return err
	}
	if len(rows) == 0 && collectionErr != nil {
		return collectionErr
	}
	if err = e.store.put("state", "baseline", map[string]any{"done": true, "finished_at": time.Now().UTC()}); err != nil {
		return err
	}
	selected := 0
	for _, v := range rows {
		if v.Selected {
			selected++
		}
	}
	text := fmt.Sprintf("首次漏洞采集已结束，共入库%d条，其中%d条通过筛选。首次采集不会逐条推送，也不会批量调用AI修复，请访问平台漏洞列表查看详细信息。", len(rows), selected)
	if collectionErr != nil {
		text += "\n部分来源失败，详情请查看通知与任务。"
	}
	link := ""
	if cfg.Branding.PublicURL != "" {
		link = strings.TrimRight(cfg.Branding.PublicURL, "/") + "/?view=vulnerabilities"
	}
	if err = e.notifyAll(ctx, cfg, "首次漏洞采集完成", text, link, nil); err != nil {
		return err
	}
	return collectionErr
}
