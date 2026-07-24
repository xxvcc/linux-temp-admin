package expiry

import (
	"testing"
	"time"
)

// The expiry date must never lock the account before the requested window
// (usable for at least `hours`), yet stay within ~1 extra day — across every
// hour-of-day a creation might happen at.
func TestNeverPrematureWithinOneDay(t *testing.T) {
	base := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	for _, hours := range []int{1, 6, 12, 23, 24, 25, 48, 168, 8760} {
		for hod := 0; hod < 24; hod++ { // creation at each hour of the day
			for _, min := range []int{0, 11, 59} {
				now := base.Add(time.Duration(hod)*time.Hour + time.Duration(min)*time.Minute)
				date := Date(now, hours)
				lock, err := LockInstant(date)
				if err != nil {
					t.Fatalf("LockInstant(%q): %v", date, err)
				}
				window := now.UTC().Add(time.Duration(hours) * time.Hour)
				if lock.Before(window) {
					t.Errorf("hours=%d now=%s: lock %s is before now+hours %s (premature)",
						hours, now.Format(time.RFC3339), lock.Format(time.RFC3339), window.Format(time.RFC3339))
				}
				if lock.After(window.Add(24 * time.Hour)) {
					t.Errorf("hours=%d now=%s: lock %s is more than 1 day past the window %s",
						hours, now.Format(time.RFC3339), lock.Format(time.RFC3339), window.Format(time.RFC3339))
				}
			}
		}
	}
}

func TestDateIsPlusHoursPlusOneDay(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	// 24h + 1 day = +2 days exactly (independent of hour-of-day for multiples of 24)
	if got, want := Date(now, 24), "2026-07-09"; got != want {
		t.Errorf("Date(+24h) = %q, want %q", got, want)
	}
	// 6h from 12:00 -> now+6h = 18:00 same day -> +1 day -> next day
	if got, want := Date(now, 6), "2026-07-08"; got != want {
		t.Errorf("Date(+6h) = %q, want %q", got, want)
	}
}
