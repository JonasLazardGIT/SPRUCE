package prf

import (
	"math/rand"
	"path/filepath"
	"runtime"
	"testing"
)

// TestVectorsFromParams loads prf_params.json, samples a deterministic key/nonce,
// and computes a tag to ensure the pipeline (load -> permute -> truncate) works.
// This is a smoke test that also serves as a reference vector generator: run
// with -v to see the tag printed in decimal form.
func TestVectorsFromParams(t *testing.T) {
	paramsPath := pathToParams(t)
	p, err := LoadParamsFromFile(paramsPath)
	if err != nil {
		t.Fatalf("load params: %v", err)
	}

	// Deterministic RNG for reproducible vectors.
	rng := rand.New(rand.NewSource(42))
	f := NewField(p.Q)

	key := make([]Elem, p.LenKey)
	nonce := make([]Elem, p.LenNonce)
	fillRandom := func(dst []Elem) {
		for i := range dst {
			dst[i] = Elem(uint64(rng.Int63()) % f.Q())
		}
	}
	fillRandom(key)
	fillRandom(nonce)

	tag, err := Tag(key, nonce, p)
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}

	// Compute again to ensure determinism.
	tag2, err := Tag(key, nonce, p)
	if err != nil {
		t.Fatalf("Tag second: %v", err)
	}
	if len(tag) != len(tag2) {
		t.Fatalf("tag length mismatch: %d vs %d", len(tag), len(tag2))
	}
	for i := range tag {
		if tag[i] != tag2[i] {
			t.Fatalf("tag mismatch at %d: %d vs %d", i, tag[i], tag2[i])
		}
	}

	// Log a compact view of the inputs/outputs as decimal coefficients.
	t.Logf("params: q=%d d=%d t=%d RF=%d RP=%d", p.Q, p.D, p.T(), p.RF, p.RP)
	t.Logf("key[0:4]=%v nonce[0:4]=%v", key[:min(4, len(key))], nonce[:min(4, len(nonce))])
	t.Logf("tag=%v", tag)
}

func pathToParams(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	return filepath.Join(dir, "prf_params.json")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
