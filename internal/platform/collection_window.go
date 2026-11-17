package platform

import "time"

func collectionWindow(c CollectorConfig) (string, string) {
	if c.WindowStart != "" && c.WindowEnd != "" {
		return c.WindowStart, c.WindowEnd
	}
	if !c.NoSleep {
		return "07:00", "00:00"
	}
	return "00:00", "00:00"
}
func withinCollectionWindow(c CollectorConfig, now time.Time) bool {
	start, end := collectionWindow(c)
	a, err := time.Parse("15:04", start)
	if err != nil {
		return false
	}
	b, err := time.Parse("15:04", end)
	if err != nil {
		return false
	}
	s := a.Hour()*60 + a.Minute()
	e := b.Hour()*60 + b.Minute()
	n := now.Hour()*60 + now.Minute()
	if s == e {
		return true
	}
	if s < e {
		return n >= s && n < e
	}
	return n >= s || n < e
}
