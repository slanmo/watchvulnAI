package platform

import (
	"context"
	"errors"
	"time"
)

var reportZone = time.FixedZone("UTC+8", 8*3600)

type reportPeriod struct{ Start, End time.Time }
type reportPeriodKey struct{}

func parseReportPeriod(start, end string) (reportPeriod, error) {
	a, err := time.ParseInLocation("2006-01-02", start, reportZone)
	if err != nil {
		return reportPeriod{}, errors.New("开始日期格式须为YYYY-MM-DD")
	}
	b, err := time.ParseInLocation("2006-01-02", end, reportZone)
	if err != nil {
		return reportPeriod{}, errors.New("结束日期格式须为YYYY-MM-DD")
	}
	b = b.AddDate(0, 0, 1)
	if !a.Before(b) || b.Sub(a) > 366*24*time.Hour {
		return reportPeriod{}, errors.New("日期范围必须正序且不超过366天")
	}
	if a.After(time.Now()) {
		return reportPeriod{}, errors.New("开始日期不能晚于当前时间")
	}
	return reportPeriod{a, b}, nil
}
func withReportPeriod(ctx context.Context, start, end string) (context.Context, error) {
	p, err := parseReportPeriod(start, end)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, reportPeriodKey{}, p), nil
}
