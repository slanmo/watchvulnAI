package platform

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type callWriterKey struct{}

func (e *Engine) callEvent(ctx context.Context, kind, content string) error {
	call, _ := ctx.Value(callContextKey{}).(string)
	report, _ := ctx.Value(reportContextKey{}).(string)
	if call == "" {
		return e.event(ctx, kind, content)
	}
	if kind == "delta" || kind == "output" {
		id := call + ":output"
		v := ReportEvent{ID: id, ReportID: report, CallID: call, Kind: "output", CreatedAt: time.Now().UTC()}
		err := e.store.get("report_event", id, &v)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if kind == "delta" {
			v.Content += content
		} else {
			v.Content = content
		}
		return e.store.put("report_event", id, v)
	}
	v := ReportEvent{ID: ID(), ReportID: report, CallID: call, Kind: kind, Content: content, CreatedAt: time.Now().UTC()}
	return e.store.put("report_event", v.ID, v)
}
