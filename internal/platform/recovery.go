package platform

import "time"

func (e *Engine) RecoverInterrupted() error {
	reports, err := e.store.Reports()
	if err != nil {
		return err
	}
	for _, r := range reports {
		if r.Status == "queued" || r.Status == "generating" {
			r.Status = "failed"
			r.Error = "服务重启导致任务中断，请重新生成"
			if err = e.store.PutReport(r); err != nil {
				return err
			}
		}
	}
	jobs := []CollectionJob{}
	if err = e.store.all("collection_job", &jobs); err != nil {
		return err
	}
	for _, j := range jobs {
		if j.Status == "running" {
			j.Status = "failed"
			j.Error = "服务重启导致采集任务中断"
			j.FinishedAt = time.Now().UTC()
			if err = e.store.put("collection_job", j.ID, j); err != nil {
				return err
			}
		}
	}
	health, err := e.SourceStatuses()
	if err != nil {
		return err
	}
	for _, h := range health {
		if h.Status == "checking" {
			h.Status = "failed"
			h.Error = "服务重启导致检查中断"
			if err = e.store.put("source_health", h.Source, h); err != nil {
				return err
			}
		}
	}
	solutions := []SolutionJob{}
	if err = e.store.all("solution_job", &solutions); err != nil {
		return err
	}
	for _, j := range solutions {
		if j.Status == "running" {
			j.Status = "failed"
			j.Error = "服务重启导致修复生成中断"
			j.FinishedAt = time.Now().UTC()
			if err = e.store.put("solution_job", j.ID, j); err != nil {
				return err
			}
		}
	}
	pushes := []PushJob{}
	if err = e.store.all("push_job", &pushes); err != nil {
		return err
	}
	for _, j := range pushes {
		if j.Status == "running" {
			j.Status = "failed"
			j.Error = "服务重启导致推送任务中断"
			j.FinishedAt = time.Now().UTC()
			if err = e.store.put("push_job", j.ID, j); err != nil {
				return err
			}
		}
	}
	return nil
}
