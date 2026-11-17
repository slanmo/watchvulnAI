package platform

import (
	"context"
	"time"
)

func (e *Engine) RetryDeliveries(ctx context.Context) error {
	cfg, err := e.store.Config()
	if err != nil {
		return err
	}
	items, err := e.store.Deliveries()
	if err != nil {
		return err
	}
	for _, d := range items {
		if d.Status == "sent" || d.Attempts >= 8 || time.Now().Before(d.NextAttempt) {
			continue
		}
		var channel *Notification
		for i := range cfg.Notifications {
			if cfg.Notifications[i].ID == d.ChannelID && cfg.Notifications[i].Enabled {
				channel = &cfg.Notifications[i]
				break
			}
		}
		if channel == nil {
			continue
		}
		var report *Report
		if d.ReportID != "" {
			r, err := e.store.Report(d.ReportID)
			if err != nil {
				return err
			}
			report = &r
		}
		task := ctx
		if d.Vulnerability != nil {
			task = context.WithValue(ctx, vulnerabilityContextKey{}, d.Vulnerability)
		}
		err = sendNotification(task, *channel, d.Title, d.Text, d.Link, report)
		d.Attempts++
		d.Status = "sent"
		d.Error = ""
		if err != nil {
			d.Status = "failed"
			d.Error = err.Error()
			d.NextAttempt = time.Now().Add(time.Minute * time.Duration(1<<min(d.Attempts, 6)))
		}
		if err = e.store.PutDelivery(d); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}
