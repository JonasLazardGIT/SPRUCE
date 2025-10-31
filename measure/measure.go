package measure

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var Enabled bool
var Global Counter

func init() {
	Enabled = os.Getenv("MEASURE_SIZES") == "1"
	Global = Counter{M: make(map[string]int64)}
}

func BytesField(q *big.Int) int {
	// ceil(bitlen(q)/8)
	if q == nil {
		return 0
	}
	b := q.BitLen()
	return (b + 7) / 8
}

func BytesRing(phi int, q *big.Int) int {
	return phi * BytesField(q)
}

func BytesPolyDegree(d int, bytesF int) int {
	return (d + 1) * bytesF
}

func Human(n int64) string {
	const (
		KiB = 1024
		MiB = 1024 * KiB
	)
	switch {
	case n >= MiB:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(MiB))
	case n >= KiB:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(KiB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

type Counter struct {
	mu sync.Mutex
	M  map[string]int64
}

func (c *Counter) Add(key string, n int64) {
	if !Enabled {
		return
	}
	c.mu.Lock()
	c.M[key] += n
	c.mu.Unlock()
}

// SnapshotAndReset returns the current map of measurements and clears it.
// Keys map to the number of bytes recorded for that measurement. If measuring
// is disabled, it returns an empty map.
func (c *Counter) SnapshotAndReset() map[string]uint64 {
	if !Enabled {
		return map[string]uint64{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.M))
	for k, v := range c.M {
		out[k] = uint64(v)
	}
	c.M = make(map[string]int64)
	return out
}

func (c *Counter) Dump() {
	if !Enabled {
		return
	}
	fmt.Println("[measure] Size report:")
	// Print to stdout in a stable order
	keys := make([]string, 0, len(c.M))
	for k := range c.M {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := c.M[k]
		fmt.Printf("[measure] %s = %s\n", k, Human(v))
	}

	// Also persist to a JSON file
	_ = os.MkdirAll(defaultOutDir(), 0o755)
	outPath := outFilePath()
	if err := c.dumpToJSON(outPath); err != nil {
		fmt.Printf("[measure] failed writing report to %s: %v\n", outPath, err)
	} else {
		fmt.Printf("[measure] wrote report to %s\n", outPath)
	}
}

func Section(name string, f func()) {
	if !Enabled {
		f()
		return
	}
	fmt.Printf("[measure] Begin %s\n", name)
	f()
	fmt.Printf("[measure] End %s\n", name)
}

// dumpToJSON persists the current counter map to a pretty JSON file.
func (c *Counter) dumpToJSON(path string) error {
	// Build a stable list of entries
	keys := make([]string, 0, len(c.M))
	for k := range c.M {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type entry struct {
		Key   string `json:"key"`
		Bytes int64  `json:"bytes"`
		Human string `json:"human"`
	}
	payload := struct {
		Timestamp string  `json:"timestamp"`
		Entries   []entry `json:"entries"`
	}{
		Timestamp: time.Now().Format("20060102_150405"),
		Entries:   make([]entry, 0, len(keys)),
	}
	for _, k := range keys {
		v := c.M[k]
		payload.Entries = append(payload.Entries, entry{Key: k, Bytes: v, Human: Human(v)})
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// defaultOutDir returns the folder to write size reports to.
// Override with MEASURE_SIZES_DIR if set.
func defaultOutDir() string {
	if d := os.Getenv("MEASURE_SIZES_DIR"); d != "" {
		return d
	}
	return "Measure_Reports"
}

// outFilePath returns the output file path for the current time.
// Override with MEASURE_SIZES_FILE if set.
func outFilePath() string {
	if p := os.Getenv("MEASURE_SIZES_FILE"); p != "" {
		// If a dir is provided, create a default filename inside it.
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return filepath.Join(p, defaultFileName())
		}
		// Else treat as full file path.
		return p
	}
	return filepath.Join(defaultOutDir(), defaultFileName())
}

func defaultFileName() string {
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("sizes_%s.json", ts)
}
