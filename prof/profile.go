package prof

import (
	"sync"
	"time"
)

// Entry represents a single timing measurement.
type Entry struct {
	Label string
	Dur   time.Duration
}

var (
	mu     sync.Mutex
	record []Entry
)

// Track logs the duration since start with the given name.
func Track(start time.Time, name string) {
	elapsed := time.Since(start)
	mu.Lock()
	record = append(record, Entry{Label: name, Dur: elapsed})
	mu.Unlock()
}

// SnapshotAndReset returns the collected timing entries and clears them.
func SnapshotAndReset() []Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, len(record))
	copy(out, record)
	record = nil
	return out
}
