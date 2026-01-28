package utils

import (
	"fmt"
	"time"
)

// Time constants
const (
	DateFormat     = "2006-01-02"
	DateTimeFormat = "2006-01-02 15:04:05"
	TimeFormat     = "15:04:05"
	RFC3339Format  = time.RFC3339
)

// ParseDate parses date string
func ParseDate(dateStr string) (time.Time, error) {
	return time.Parse(DateFormat, dateStr)
}

// ParseDateTime parses datetime string
func ParseDateTime(datetimeStr string) (time.Time, error) {
	return time.Parse(DateTimeFormat, datetimeStr)
}

// FormatDate formats time to date string
func FormatDate(t time.Time) string {
	return t.Format(DateFormat)
}

// FormatDateTime formats time to datetime string
func FormatDateTime(t time.Time) string {
	return t.Format(DateTimeFormat)
}

// NowUTC returns current time in UTC
func NowUTC() time.Time {
	return time.Now().UTC()
}

// BeginningOfDay returns beginning of day for given time
func BeginningOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

// EndOfDay returns end of day for given time
func EndOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 23, 59, 59, 999999999, t.Location())
}

// AddDays adds days to time
func AddDays(t time.Time, days int) time.Time {
	return t.AddDate(0, 0, days)
}

// AddMonths adds months to time
func AddMonths(t time.Time, months int) time.Time {
	return t.AddDate(0, months, 0)
}

// AddYears adds years to time
func AddYears(t time.Time, years int) time.Time {
	return t.AddDate(years, 0, 0)
}

// IsToday checks if time is today
func IsToday(t time.Time) bool {
	now := time.Now()
	return t.Year() == now.Year() && t.Month() == now.Month() && t.Day() == now.Day()
}

// IsPast checks if time is in the past
func IsPast(t time.Time) bool {
	return t.Before(time.Now())
}

// IsFuture checks if time is in the future
func IsFuture(t time.Time) bool {
	return t.After(time.Now())
}

// CalculateAge calculates age from birth date
func CalculateAge(birthDate time.Time) int {
	now := time.Now()
	years := now.Year() - birthDate.Year()

	// Adjust if birthday hasn't occurred this year
	if now.YearDay() < birthDate.YearDay() {
		years--
	}

	return years
}

// HumanReadableDuration returns human readable duration
func HumanReadableDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}

	if d < time.Hour {
		minutes := d.Minutes()
		return fmt.Sprintf("%.0f minutes", minutes)
	}

	if d < 24*time.Hour {
		hours := d.Hours()
		return fmt.Sprintf("%.0f hours", hours)
	}

	days := d.Hours() / 24
	return fmt.Sprintf("%.0f days", days)
}

// TimeDiffInDays calculates difference in days
func TimeDiffInDays(t1, t2 time.Time) int {
	duration := t2.Sub(t1)
	return int(duration.Hours() / 24)
}

// GetTimeZoneOffset returns timezone offset in hours
func GetTimeZoneOffset(t time.Time) string {
	_, offset := t.Zone()
	hours := offset / 3600
	minutes := (offset % 3600) / 60

	sign := "+"
	if hours < 0 {
		sign = "-"
		hours = -hours
	}

	return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
}
