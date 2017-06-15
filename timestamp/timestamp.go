package timestamp

import (
	"time"
)

// TimeToTimestamp generates a millisecond timestamp from the time object.
func TimeToTimestamp(t time.Time) uint64 {
	return uint64(t.UnixNano() / 1000000)
}

// TimestampToTime generates a time object from a millisecond timestamp.
func TimestampToTime(t uint64) time.Time {
	return time.Unix(0, int64(t)*1000000)
}

// Now returns a millisecond timestamp for now.
func Now() uint64 {
	return TimeToTimestamp(time.Now())
}
