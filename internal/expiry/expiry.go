// Package expiry computes account-expiry dates for chage -E.
//
// chage -E is day-granular and locks the account at 00:00 UTC of the given date.
// To keep an account usable for at least the requested window on every timezone
// and creation time, the revoke deadline is rounded up to a whole minute and the
// chage date is anchored to the first UTC midnight strictly after it. Scheduler
// downtime and retries can delay deletion; chage only backstops it and must not
// lock before the deadline.
package expiry

import (
	"fmt"
	"time"
)

const dateLayout = "2006-01-02"

// Deadline returns the single absolute revoke deadline shared by display,
// chage, and every scheduler backend. Rounding up accommodates at(1)'s
// minute-granular absolute format without ever shortening the requested window.
func Deadline(now time.Time, hours int) time.Time {
	target := now.Add(time.Duration(hours) * time.Hour)
	minute := target.Truncate(time.Minute)
	if target.Equal(minute) {
		return minute
	}
	return minute.Add(time.Minute)
}

// Date returns the chage -E backstop date (YYYY-MM-DD, UTC) for deadline.
func Date(deadline time.Time) string {
	return deadline.UTC().AddDate(0, 0, 1).Format(dateLayout)
}

// LockInstant returns the UTC instant at which chage disables the account for a
// given expiry date (00:00 UTC of that date). Used for reasoning/tests.
func LockInstant(date string) (time.Time, error) {
	return time.ParseInLocation(dateLayout, date, time.UTC)
}

// Display formats the shared revoke deadline for the invite output and the
// status table. Date supplies only the later day-granularity lockout backstop.
//
// It renders the UTC instant every scheduler backend actually fires on. The
// previous local-time-with-abbreviation form was ambiguous to the one reader who
// acts on it: a recipient elsewhere reads the server's "CST" as their own and can
// be wrong about the account's lifetime by a whole working day. Zone
// abbreviations are not unique and Go prints whatever the host's database calls
// the zone, so no abbreviation can be made safe here.
func Display(deadline time.Time) string {
	return deadline.UTC().Format("2006-01-02 15:04:05 UTC")
}

// DisplayServerLocal renders the same instant in the server's own zone with a
// numeric offset, for the one line of invite output that shows the operator what
// the deadline means locally. It returns "" when the server already runs UTC, so
// the caller prints nothing rather than the same time twice.
func DisplayServerLocal(deadline time.Time) string {
	if _, offset := deadline.Zone(); offset == 0 {
		return ""
	}
	return deadline.Format("2006-01-02 15:04:05 -0700")
}

// ParseDisplay recovers an absolute deadline only from unambiguous registry
// formats. Historical zone abbreviations such as CST cannot identify an instant
// without the original host timezone and must not silently become UTC.
func ParseDisplay(value string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05 UTC", "2006-01-02 15:04:05 -0700", time.RFC3339} {
		if deadline, err := time.Parse(layout, value); err == nil {
			return deadline, nil
		}
	}
	return time.Time{}, fmt.Errorf("expiry has no verifiable absolute deadline: %q (requires UTC or numeric offset)", value)
}
