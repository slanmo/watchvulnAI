package platform

import (
	"encoding/json"
	"sort"
	"strings"
)

func (s *Store) SaveConfigAndRefilter(cfg Config) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT payload FROM platform_objects WHERE kind='vulnerability'")
	if err != nil {
		return 0, err
	}
	items := []Vulnerability{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return 0, err
		}
		var v Vulnerability
		if err = json.Unmarshal([]byte(raw), &v); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	seen := map[string]bool{}
	changed := 0
	for _, v := range items {
		selected, reason := RulesMatch(v, cfg.Rules)
		valuable := v.Valuable || v.Selected || v.FilterReason == "手动排除" || strings.HasPrefix(v.FilterReason, "命中黑名单") || v.FilterReason == "未命中白名单" || v.FilterReason == "重复CVE"
		if v.Source == "chaitin" {
			valuable = severityGroup(v.Severity) == "严重" || severityGroup(v.Severity) == "高危"
			v.Valuable = valuable
		}
		if !cfg.Collector.NoFilter && !valuable {
			selected = false
			reason = "未通过上游高价值筛选"
		}
		cve := strings.ToUpper(strings.TrimSpace(v.CVE))
		if selected && cfg.Collector.EnableCVEFilter && cve != "" {
			if seen[cve] {
				selected = false
				reason = "重复CVE"
			} else {
				seen[cve] = true
			}
		}
		if v.Selected != selected || v.FilterReason != reason {
			changed++
		}
		v.Selected = selected
		v.FilterReason = reason
		raw, err := json.Marshal(v)
		if err != nil {
			return 0, err
		}
		if _, err = tx.Exec(s.q("UPDATE platform_objects SET payload=? WHERE kind='vulnerability' AND id=?"), string(raw), v.ID); err != nil {
			return 0, err
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(s.q("UPDATE platform_objects SET payload=? WHERE kind='config' AND id='main'"), string(raw)); err != nil {
		return 0, err
	}
	return changed, tx.Commit()
}
