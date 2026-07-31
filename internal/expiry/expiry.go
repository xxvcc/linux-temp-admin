// Package expiry computes account-expiry dates for chage -E.
//
// chage -E is day-granular and locks the account at 00:00 UTC of the given date.
// To keep an account usable for at least the requested window on every timezone
// and creation time, the revoke deadline is rounded up to a whole minute and the
// chage date is anchored to the first UTC midnight strictly after it. Scheduler
// downtime and retries can delay deletion; chage only backstops it and must not
// lock before the deadline.
package expiry

import "time"

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

// DisplayLocal formats the shared revoke deadline for the invite output. Date
// supplies only the later day-granularity lockout backstop.
func DisplayLocal(deadline time.Time) string {
	return deadline.Format("2006-01-02 15:04:05 MST")
}
