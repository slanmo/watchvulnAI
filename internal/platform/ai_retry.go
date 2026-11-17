package platform

import (
	"context"
	"fmt"
	"time"
)

func retryAnalysis(ctx context.Context, retries int, delay time.Duration, call func(context.Context) (aiAnalysis, error)) (aiAnalysis, error) {
	var result aiAnalysis
	var err error
	if retries < 0 || retries > 20 {
		return result, fmt.Errorf("失败重试次数必须为0至20")
	}
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if attempt > 0 {
			wait := delay * time.Duration(1<<min(attempt-1, 4))
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, fmt.Errorf("已尝试%d次，重试取消: %w", attempt, ctx.Err())
			case <-timer.C:
			}
		}
		result, err = call(ctx)
		if err == nil {
			return result, nil
		}
		if eventErr := recordEvent(ctx, "retry", fmt.Sprintf("第%d次尝试失败: %v", attempt+1, err)); eventErr != nil {
			return result, eventErr
		}
		if ctx.Err() != nil {
			return result, fmt.Errorf("已尝试%d次，请求取消: %w", attempt+1, ctx.Err())
		}
	}
	return result, fmt.Errorf("首次请求及%d次失败重试均失败（共%d次尝试）: %w", retries, retries+1, err)
}

func analyzeWithRetry(ctx context.Context, cfg AIConfig, input any) (aiAnalysis, error) {
	return retryAnalysis(ctx, cfg.RetryCount, time.Second, func(ctx context.Context) (aiAnalysis, error) {
		return analyzeInput(context.WithValue(ctx, callContextKey{}, ID()), cfg, input)
	})
}
