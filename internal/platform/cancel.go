package platform

import "errors"

func (e *Engine) CancelReport(id string) error {
	e.jobMu.Lock()
	defer e.jobMu.Unlock()
	if !e.reportRunning || e.reportID != id || e.reportCancel == nil {
		return errors.New("报告任务未运行或已经结束")
	}
	r, err := e.store.Report(id)
	if err != nil {
		return err
	}
	if r.Status != "queued" && r.Status != "generating" {
		return errors.New("报告已结束")
	}
	e.reportCancel()
	return nil
}
