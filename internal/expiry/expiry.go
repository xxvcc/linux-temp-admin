// Package expiry computes account-expiry dates for chage -E.
//
// chage -E is day-granular and locks the account at 00:00 UTC of the given date.
// To keep an account usable for at least the requested window on every timezone
// and creation time — and never lock it prematurely — the expiry date is
// anchored to the first midnight strictly after now+hours (the date of
// now+hours, plus one day). When an auto-delete timer is set it fires precisely
// at now+hours; chage only backstops it and must not lock before it.
package expiry

import "time"

const dateLayout = "2006-01-02"

// Date returns the chage -E expiry date (YYYY-MM-DD, UTC) for an account created
// at now with the given lifetime in hours.
func Date(now time.Time, hours int) string {
	return now.UTC().Add(time.Duration(hours)*time.Hour).AddDate(0, 0, 1).Format(dateLayout)
}

// LockInstant returns the UTC instant at which chage disables the account for a
// given expiry date (00:00 UTC of that date). Used for reasoning/tests.
func LockInstant(date string) (time.Time, error) {
	return time.ParseInLocation(dateLayout, date, time.UTC)
}

// DisplayLocal returns a human-readable local-time expiry for the invite output
// (now + hours). This is informational; Date is what actually enforces expiry.
func DisplayLocal(now time.Time, hours int) string {
	return now.Add(time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05 MST")
}
