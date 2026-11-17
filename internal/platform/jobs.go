package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type reportContextKey struct{}
type configContextKey struct{}
type callContextKey struct{}
type ReportEvent struct {
	ID        string    `json:"id"`
	ReportID  string    `json:"report_id"`
	Kind      string    `json:"kind"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	CallID    string    `json:"call_id,omitempty"`
}
type CollectionJob struct {
	Baseline   bool      `json:"baseline"`
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

func taskConfig(ctx context.Context, s *Store) (Config, error) {
	if c, ok := ctx.Value(configContextKey{}).(Config); ok {
		return c, nil
	}
	return s.Config()
}
func (e *Engine) event(ctx context.Context, kind, content string) error {
	id, _ := ctx.Value(reportContextKey{}).(string)
	if id == "" {
		return nil
	}
	v := ReportEvent{ID: ID(), ReportID: id, Kind: kind, Content: content, CreatedAt: time.Now().UTC()}
	return e.store.put("report_event", v.ID, v)
}
func recordEvent(ctx context.Context, kind, content string) error {
	if writer, ok := ctx.Value(callWriterKey{}).(func(context.Context, string, string) error); ok {
		return writer(ctx, kind, content)
	}
	fn, _ := ctx.Value(eventContextKey{}).(func(string, string) error)
	if fn == nil {
		return nil
	}
	return fn(kind, content)
}

type eventContextKey struct{}

func (e *Engine) StartReport(ctx context.Context, kind string, send bool) (Report, error) {
	if kind != "daily" && kind != "weekly" && kind != "custom" {
		return Report{}, errors.New("报告类型无效")
	}
	e.jobMu.Lock()
	if e.reportRunning {
		e.jobMu.Unlock()
		return Report{}, errors.New("报告生成任务正在执行")
	}
	e.reportRunning = true
	e.jobMu.Unlock()
	cfg, err := e.store.Config()
	if err != nil {
		e.jobMu.Lock()
		e.reportRunning = false
		e.jobMu.Unlock()
		return Report{}, err
	}
	r := Report{ID: ID(), Kind: kind, Title: map[string]string{"daily": "漏洞风险分析日报", "weekly": "漏洞风险分析周报", "custom": "漏洞风险分析 · 自定义周期"}[kind] + " · " + time.Now().In(reportZone).Format("2006-01-02"), Status: "queued", CreatedAt: time.Now().UTC(), VulnerabilityIDs: []string{}}
	if err = e.store.PutReport(r); err != nil {
		e.jobMu.Lock()
		e.reportRunning = false
		e.jobMu.Unlock()
		return Report{}, err
	}
	taskCtx, cancel := context.WithCancel(ctx)
	e.jobMu.Lock()
	e.reportCancel = cancel
	e.reportID = r.ID
	e.jobMu.Unlock()
	go func() {
		defer cancel()
		defer func() {
			e.jobMu.Lock()
			e.reportRunning = false
			e.reportCancel = nil
			e.reportID = ""
			e.jobMu.Unlock()
		}()
		task := context.WithValue(taskCtx, reportContextKey{}, r.ID)
		task = context.WithValue(task, configContextKey{}, cfg)
		_, err := e.Generate(task, kind)
		if err == nil && send {
			err = e.SendReport(task, r.ID)
		}
		if err != nil {
			_ = e.event(task, "error", err.Error())
		}
	}()
	return r, nil
}
func (e *Engine) StartCollection(ctx context.Context) (CollectionJob, error) {
	e.jobMu.Lock()
	if e.collectionRunning {
		e.jobMu.Unlock()
		return CollectionJob{}, errors.New("采集任务正在执行")
	}
	e.collectionRunning = true
	e.jobMu.Unlock()
	cfg, err := e.store.Config()
	if err != nil {
		e.jobMu.Lock()
		e.collectionRunning = false
		e.jobMu.Unlock()
		return CollectionJob{}, err
	}
	baseline, err := e.needsBaseline()
	if err != nil {
		e.jobMu.Lock()
		e.collectionRunning = false
		e.jobMu.Unlock()
		return CollectionJob{}, err
	}
	job := CollectionJob{ID: ID(), Status: "running", CreatedAt: time.Now().UTC()}
	job.Baseline = baseline
	if err = e.store.put("collection_job", job.ID, job); err != nil {
		e.jobMu.Lock()
		e.collectionRunning = false
		e.jobMu.Unlock()
		return CollectionJob{}, err
	}
	go func() {
		defer func() { e.jobMu.Lock(); e.collectionRunning = false; e.jobMu.Unlock() }()
		task := context.WithValue(ctx, configContextKey{}, cfg)
		if baseline {
			task = context.WithValue(task, baselineContextKey{}, true)
		}
		err := e.Collect(task)
		if baseline && ctx.Err() == nil {
			if finishErr := e.finishBaseline(task, cfg, err); finishErr != nil {
				err = finishErr
			}
		}
		job.Status = "ready"
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
		}
		job.FinishedAt = time.Now().UTC()
		_ = e.store.put("collection_job", job.ID, job)
	}()
	return job, nil
}
func (e *Engine) DeleteReport(id string) error {
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	r, err := e.store.Report(id)
	if err != nil {
		return err
	}
	if r.Status == "queued" || r.Status == "generating" {
		return errors.New("运行中的报告不能删除")
	}
	tx, err := e.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, kind := range []string{"report_event", "delivery"} {
		rows, err := tx.Query(e.store.q("SELECT id,payload FROM platform_objects WHERE kind=?"), kind)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var key, raw string
			if err = rows.Scan(&key, &raw); err != nil {
				rows.Close()
				return err
			}
			var v struct {
				ReportID string `json:"report_id"`
			}
			if err = json.Unmarshal([]byte(raw), &v); err != nil {
				rows.Close()
				return err
			}
			if v.ReportID == id {
				ids = append(ids, key)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, key := range ids {
			if _, err = tx.Exec(e.store.q("DELETE FROM platform_objects WHERE kind=? AND id=?"), kind, key); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(e.store.q("DELETE FROM platform_objects WHERE kind='report' AND id=?"), id); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) PruneReports() error {
	cfg, err := e.store.Config()
	if err != nil {
		return err
	}
	if cfg.AI.RetentionDays == 0 {
		return nil
	}
	reports, err := e.store.Reports()
	if err != nil {
		return err
	}
	cutoff := time.Now().AddDate(0, 0, -cfg.AI.RetentionDays)
	for _, r := range reports {
		if r.CreatedAt.Before(cutoff) && r.Status != "queued" && r.Status != "generating" {
			if err = e.DeleteReport(r.ID); err != nil {
				return fmt.Errorf("清理报告: %w", err)
			}
		}
	}
	return nil
}
