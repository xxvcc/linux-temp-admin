package expiry

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDeadlineRoundsUpWithoutShorteningRequestedWindow(t *testing.T) {
	loc := time.FixedZone("test", 8*60*60)
	for _, tc := range []struct {
		now  time.Time
		want time.Time
	}{
		{
			now:  time.Date(2026, 7, 7, 12, 34, 0, 0, loc),
			want: time.Date(2026, 7, 8, 12, 34, 0, 0, loc),
		},
		{
			now:  time.Date(2026, 7, 7, 12, 34, 0, 1, loc),
			want: time.Date(2026, 7, 8, 12, 35, 0, 0, loc),
		},
		{
			now:  time.Date(2026, 7, 7, 12, 34, 59, 999999999, loc),
			want: time.Date(2026, 7, 8, 12, 35, 0, 0, loc),
		},
	} {
		got := Deadline(tc.now, 24)
		if !got.Equal(tc.want) || got.Location() != loc {
			t.Errorf("Deadline(%s) = %s (%s), want %s (%s)", tc.now, got, got.Location(), tc.want, loc)
		}
		requested := tc.now.Add(24 * time.Hour)
		if got.Before(requested) || got.Sub(requested) >= time.Minute {
			t.Errorf("deadline offset from requested target = %s, want [0, 1m)", got.Sub(requested))
		}
	}
}

func TestDeadlineUsesElapsedHoursAcrossDST(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		now   time.Time
		hours int
		want  time.Time
	}{
		{
			name:  "spring forward full day",
			now:   time.Date(2026, 3, 7, 12, 34, 59, 0, loc),
			hours: 24,
			want:  time.Date(2026, 3, 8, 13, 35, 0, 0, loc),
		},
		{
			name:  "fall back full day",
			now:   time.Date(2026, 10, 31, 12, 34, 59, 0, loc),
			hours: 24,
			want:  time.Date(2026, 11, 1, 11, 35, 0, 0, loc),
		},
		{
			name:  "spring gap one hour",
			now:   time.Date(2026, 3, 8, 1, 30, 59, 0, loc),
			hours: 1,
			want:  time.Date(2026, 3, 8, 3, 31, 0, 0, loc),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Deadline(tc.now, tc.hours); !got.Equal(tc.want) {
				t.Fatalf("Deadline(%s, %d) = %s, want %s", tc.now, tc.hours, got, tc.want)
			}
		})
	}
}

// The expiry date must never lock the account before the shared deadline, yet
// stay within one extra day across every hour-of-day a creation might happen at.
func TestNeverPrematureWithinOneDay(t *testing.T) {
	base := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	for _, hours := range []int{1, 6, 12, 23, 24, 25, 48, 168, 8760} {
		for hod := 0; hod < 24; hod++ { // creation at each hour of the day
			for _, min := range []int{0, 11, 59} {
				now := base.Add(time.Duration(hod)*time.Hour + time.Duration(min)*time.Minute)
				deadline := Deadline(now, hours)
				date := Date(deadline)
				lock, err := LockInstant(date)
				if err != nil {
					t.Fatalf("LockInstant(%q): %v", date, err)
				}
				if lock.Before(deadline) {
					t.Errorf("hours=%d now=%s: lock %s is before deadline %s (premature)",
						hours, now.Format(time.RFC3339), lock.Format(time.RFC3339), deadline.Format(time.RFC3339))
				}
				if lock.After(deadline.Add(24 * time.Hour)) {
					t.Errorf("hours=%d now=%s: lock %s is more than 1 day past deadline %s",
						hours, now.Format(time.RFC3339), lock.Format(time.RFC3339), deadline.Format(time.RFC3339))
				}
			}
		}
	}
}

func TestDateIsFirstUTCMidnightAfterDeadline(t *testing.T) {
	for _, tc := range []struct {
		deadline time.Time
		want     string
	}{
		{time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC), "2026-07-09"},
		{time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC), "2026-07-09"},
		{time.Date(2026, 7, 8, 23, 59, 0, 0, time.UTC), "2026-07-09"},
	} {
		if got := Date(tc.deadline); got != tc.want {
			t.Errorf("Date(%s) = %q, want %q", tc.deadline, got, tc.want)
		}
	}
}

// TestLockInstantMatchesWhatChageActuallyStores anchors this package's model to
// the tool it models. LockInstant restates Date's own assumption — that chage
// reads the date as UTC — so every test built on it agrees with Date by
// construction and none of them can notice if chage disagrees. This one asks
// chage, against a throwaway root, and compares the stored sp_expire with the
// day count LockInstant predicts.
//
// Measured while writing it: shadow-utils on this host stores the same value
// under TZ=UTC, TZ=Pacific/Kiritimati (UTC+14) and TZ=Pacific/Honolulu (UTC-10),
// so the UTC model holds here. The point of the test is that a shadow which
// parsed the date locally would now be caught instead of agreeing with a model
// that assumed it away.
func TestLockInstantMatchesWhatChageActuallyStores(t *testing.T) {
	if _, err := exec.LookPath("chage"); err != nil {
		t.Skip("chage is not installed")
	}
	const date = "2026-09-08"
	want, err := LockInstant(date)
	if err != nil {
		t.Fatal(err)
	}
	wantDays := want.Unix() / 86400

	for _, tz := range []string{"UTC", "Pacific/Kiritimati", "Pacific/Honolulu"} {
		t.Run(tz, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"passwd":  "tu:x:4242:4242::/home/tu:/bin/sh\n",
				"shadow":  "tu:!:19000:0:99999:7:::\n",
				"group":   "tu:x:4242:\n",
				"gshadow": "tu:!::\n",
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("chage", "--root", root, "-E", date, "tu")
			cmd.Env = append(os.Environ(), "TZ="+tz)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("chage --root is unusable here: %v: %s", err, out)
			}
			shadow, err := os.ReadFile(filepath.Join(root, "etc", "shadow"))
			if err != nil {
				t.Fatal(err)
			}
			fields := strings.Split(strings.TrimSpace(string(shadow)), ":")
			if len(fields) < 8 {
				t.Fatalf("unexpected shadow shape %q", shadow)
			}
			got, err := strconv.ParseInt(fields[7], 10, 64)
			if err != nil {
				t.Fatalf("sp_expire %q is not a day count: %v", fields[7], err)
			}
			if got != wantDays {
				t.Fatalf("chage stored sp_expire=%d for %s under TZ=%s; LockInstant predicts %d. "+
					"This package's UTC model does not match the shadow on this host.", got, date, tz, wantDays)
			}
		})
	}
}
