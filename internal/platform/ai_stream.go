package platform

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func streamCompletion(ctx context.Context, cfg AIConfig, prompt, input string) (string, error) {
	body := map[string]any{"model": cfg.Model, "temperature": 0.2, "stream": true, "response_format": map[string]string{"type": "json_object"}, "messages": []map[string]string{{"role": "system", "content": prompt}, {"role": "user", "content": input}}}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(cfg.BaseURL, "/")+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	timeout := cfg.TimeoutSeconds
	if timeout == 0 {
		timeout = 300
	}
	res, err := (&http.Client{Timeout: time.Duration(timeout) * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("模型接口HTTP %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Content-Type"), "text/event-stream") {
		var response struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&response); err != nil {
			return "", err
		}
		if len(response.Choices) == 0 {
			return "", errors.New("AI返回空choices")
		}
		return response.Choices[0].Message.Content, nil
	}
	scanner := bufio.NewScanner(io.LimitReader(res.Body, 8<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var output, chunk strings.Builder
	last := time.Now()
	done := false
	flush := func() error {
		if chunk.Len() == 0 {
			return nil
		}
		err := recordEvent(ctx, "delta", chunk.String())
		chunk.Reset()
		last = time.Now()
		return err
	}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			done = true
			break
		}
		var frame struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				Finish *string `json:"finish_reason"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err = json.Unmarshal([]byte(data), &frame); err != nil {
			return "", err
		}
		if frame.Error != nil {
			return "", errors.New(frame.Error.Message)
		}
		for _, choice := range frame.Choices {
			output.WriteString(choice.Delta.Content)
			chunk.WriteString(choice.Delta.Content)
			if choice.Finish != nil {
				done = true
			}
		}
		if chunk.Len() > 2048 || time.Since(last) > time.Second {
			if err = flush(); err != nil {
				return "", err
			}
		}
	}
	if err = flush(); err != nil {
		return "", err
	}
	if err = scanner.Err(); err != nil {
		return "", err
	}
	if !done {
		return "", errors.New("模型流意外中断")
	}
	return output.String(), nil
}
