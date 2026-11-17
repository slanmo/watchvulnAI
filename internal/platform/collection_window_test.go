package platform

import (
	"testing"
	"time"
)

func TestCollectionWindow(t *testing.T) {
	for _, tc := range []struct {
		start, end, now string
		want            bool
	}{{"09:30", "18:00", "09:29", false}, {"09:30", "18:00", "09:30", true}, {"09:30", "18:00", "18:00", false}, {"22:00", "06:00", "23:10", true}, {"22:00", "06:00", "05:59", true}, {"22:00", "06:00", "06:00", false}, {"00:00", "00:00", "12:00", true}} {
		now, _ := time.Parse("15:04", tc.now)
		if got := withinCollectionWindow(CollectorConfig{WindowStart: tc.start, WindowEnd: tc.end}, now); got != tc.want {
			t.Fatalf("%+v got %v", tc, got)
		}
	}
}
