package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zema1/watchvuln/internal/grab"
	"log"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	store             *Store
	collectMu         sync.Mutex
	generateMu        sync.Mutex
	jobMu             sync.Mutex
	reportRunning     bool
	reportCancel      context.CancelFunc
	reportID          string
	collectionRunning bool
	healthRunning     bool
	solutionMu        sync.Mutex
}

func NewEngine(s *Store) *Engine { return &Engine{store: s} }
func crawler(source string) (grab.Grabber, error) {
	switch source {
	case "avd":
		return grab.NewAVDCrawler(), nil
	case "nox", "ti":
		return grab.NewTiCrawler(), nil
	case "oscs":
		return grab.NewOSCSCrawler(), nil
	case "threatbook":
		return grab.NewThreatBookCrawler(), nil
	case "seebug":
		return grab.NewSeebugCrawler(), nil
	case "struts2":
		return grab.NewStruts2Crawler(), nil
	case "kev":
		return grab.NewKEVCrawler(), nil
	case "venustech":
		return grab.NewVenustechCrawler(), nil
	case "chaitin":
		return grab.NewChaitinCrawler(), nil
	}
	return nil, fmt.Errorf("未知采集源 %s", source)
}

type collected struct {
	Vulns []Vulnerability `json:"vulns"`
	Error string          `json:"error,omitempty"`
}

// Collector subprocess isolates legacy crawler proxy/TLS environment from the web server.
func CollectorWorker(source string) error {
	g, e := crawler(source)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	limit := 3
	if os.Getenv("WATCHVULN_PROBE") == "1" {
		limit = 1
	}
	items, e := g.GetUpdate(ctx, limit)
	result := collected{Vulns: []Vulnerability{}}
	if e != nil {
		result.Error = e.Error()
	}
	for _, v := range items {
		key := v.UniqueKey
		if key == "" {
			key = v.From
		}
		if key == "" {
			key = v.Title
		}
		h := sha256.Sum256([]byte(source + ":" + key))
		selected := g.IsValuable(v)
		if os.Getenv("WATCHVULN_GITHUB_SEARCH") == "1" && v.CVE != "" {
			var search struct {
				Items []struct {
					URL string `json:"html_url"`
				} `json:"items"`
			}
			if err := getJSON(ctx, "https://api.github.com/search/repositories?q="+url.QueryEscape(v.CVE)+"&per_page=5", map[string]string{"Accept": "application/vnd.github+json", "User-Agent": "WatchVuln-AI"}, &search); err != nil {
				result.Error += " GitHub查询失败: " + err.Error()
			} else {
				for _, item := range search.Items {
					v.References = append(v.References, item.URL)
				}
			}
		}
		result.Vulns = append(result.Vulns, Vulnerability{ID: hex.EncodeToString(h[:]), Source: source, SourceID: key, Title: v.Title, CVE: v.CVE, Tags: v.Tags, Severity: string(v.Severity), Reasons: v.Reason, References: v.References, Description: v.Description, Solution: v.Solutions, URL: v.From, PublishedAt: v.Disclosure, CreatedAt: time.Now().UTC(), Selected: selected, Valuable: selected})
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
func RulesMatch(v Vulnerability, rules []Rule) (bool, string) {
	hasWhite, matchWhite := false, false
	whiteNames := []string{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		matched := false
		for _, field := range r.Fields {
			var text string
			switch field {
			case "title":
				text = v.Title
			case "tags":
				text = strings.Join(v.Tags, " ")
			case "description":
				text = v.Description
			case "solution":
				text = v.Solution
			}
			if r.Regex {
				rx, e := regexp.Compile(r.Pattern)
				matched = e == nil && rx.MatchString(text)
			} else {
				matched = strings.Contains(strings.ToLower(text), strings.ToLower(r.Pattern))
			}
			if matched {
				break
			}
		}
		if r.Kind == "black" && matched {
			return false, "命中黑名单: " + ruleName(r)
		}
		if r.Kind == "white" {
			hasWhite = true
			matchWhite = matchWhite || matched
			if matched {
				whiteNames = append(whiteNames, ruleName(r))
			}
		}
	}
	if hasWhite && !matchWhite {
		return false, "未命中白名单"
	}
	if len(whiteNames) > 0 {
		return true, "命中白名单: " + strings.Join(whiteNames, "、")
	}
	return true, "通过名单筛选"
}
func (e *Engine) Collect(ctx context.Context) error {
	if !e.collectMu.TryLock() {
		return errors.New("采集任务正在运行")
	}
	defer e.collectMu.Unlock()
	cfg, err := taskConfig(ctx, e.store)
	if err != nil {
		return err
	}
	existing, err := e.store.Vulnerabilities()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, v := range existing {
		if v.Selected && v.CVE != "" {
			seen[strings.ToUpper(v.CVE)] = true
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	errs := []string{}
	for _, source := range cfg.Collector.Sources {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		childCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		cmd := exec.CommandContext(childCtx, exe, "--collector-worker", source)
		env := []string{}
		for _, v := range os.Environ() {
			k := strings.ToUpper(strings.SplitN(v, "=", 2)[0])
			if k != "HTTP_PROXY" && k != "HTTPS_PROXY" && k != "ALL_PROXY" && k != "GO_SKIP_TLS_CHECK" {
				env = append(env, v)
			}
		}
		if cfg.Collector.Proxy != "" {
			env = append(env, "HTTP_PROXY="+cfg.Collector.Proxy, "HTTPS_PROXY="+cfg.Collector.Proxy, "ALL_PROXY="+cfg.Collector.Proxy)
		}
		if cfg.Collector.SkipTLSVerify {
			env = append(env, "GO_SKIP_TLS_CHECK=1")
		}
		if !cfg.Collector.NoGithubSearch {
			env = append(env, "WATCHVULN_GITHUB_SEARCH=1")
		}
		cmd.Env = env
		out, err := cmd.Output()
		cancel()
		if err != nil {
			errs = append(errs, source+": "+err.Error())
			continue
		}
		var res collected
		if err = json.Unmarshal(out, &res); err != nil {
			errs = append(errs, source+": 采集响应不是JSON")
			continue
		}
		if res.Error != "" {
			errs = append(errs, source+": "+sourceErrorMessage(res.Error))
		}
		for _, v := range res.Vulns {
			valuable := v.Selected || cfg.Collector.NoFilter
			v.Selected, v.FilterReason = RulesMatch(v, cfg.Rules)
			if !valuable {
				v.Selected = false
				v.FilterReason = "未通过上游高价值筛选"
			}
			cve := strings.ToUpper(strings.TrimSpace(v.CVE))
			if cfg.Collector.EnableCVEFilter && cve != "" && seen[cve] {
				v.Selected = false
				v.FilterReason = "重复CVE"
			}
			added, err := e.store.PutVulnerability(v)
			if err != nil {
				return err
			}
			if !added {
				continue
			}
			if initial, _ := ctx.Value(baselineContextKey{}).(bool); initial {
				if v.Selected && cve != "" {
					seen[cve] = true
				}
				continue
			}
			if v.Selected {
				v, err = e.enrichBeforePush(ctx, cfg, v)
				if err != nil {
					return err
				}
				if !v.Selected {
					continue
				}
				if cve != "" {
					seen[cve] = true
				}
				link := v.URL
				if cfg.Branding.PublicURL != "" {
					link = strings.TrimRight(cfg.Branding.PublicURL, "/") + "/vulnerabilities/" + url.PathEscape(v.ID)
				}
				if err = e.notifyAll(context.WithValue(ctx, vulnerabilityContextKey{}, &v), cfg, v.Title, vulnerabilityMarkdown(v), link, nil); err != nil {
					errs = append(errs, err.Error())
				}
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var lastCollect time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.PruneDeliveries(); err != nil {
				log.Printf("notification retention: %v", err)
			}
			if err := e.PruneReports(); err != nil {
				log.Printf("report retention: %v", err)
			}
			if err := e.RetryDeliveries(ctx); err != nil {
				log.Printf("retry deliveries: %v", err)
			}
			cfg, err := taskConfig(ctx, e.store)
			if err != nil {
				log.Print(err)
				continue
			}
			interval, err := time.ParseDuration(cfg.Collector.Interval)
			if err != nil {
				continue
			}
			collectionLocation, locErr := time.LoadLocation(cfg.AI.Timezone)
			if locErr != nil {
				collectionLocation = time.UTC
			}
			sleeping := !withinCollectionWindow(cfg.Collector, time.Now().In(collectionLocation))
			if cfg.Collector.Enabled && !sleeping && time.Since(lastCollect) >= interval {
				lastCollect = time.Now()
				if _, err = e.StartCollection(ctx); err != nil {
					log.Printf("collect: %v", err)
				}
			}
			if !cfg.AI.Enabled {
				continue
			}
			loc, err := time.LoadLocation(cfg.AI.Timezone)
			if err != nil {
				continue
			}
			now := time.Now().In(loc)
			if now.Hour() < cfg.AI.Hour {
				continue
			}
			kinds := []string{}
			if cfg.AI.Daily {
				kinds = append(kinds, "daily")
			}
			if cfg.AI.Weekly && int(now.Weekday()) == cfg.AI.Weekday {
				kinds = append(kinds, "weekly")
			}
			reports, err := e.store.Reports()
			if err != nil {
				continue
			}
			for _, kind := range kinds {
				done := false
				for _, r := range reports {
					if r.Kind == kind && r.CreatedAt.In(loc).Format("2006-01-02") == now.Format("2006-01-02") {
						done = true
						break
					}
				}
				if !done {
					_, err := e.StartReport(ctx, kind, true)
					if err != nil {
						log.Printf("report %s: %v", kind, err)
					}
				}
			}
		}
	}
}
