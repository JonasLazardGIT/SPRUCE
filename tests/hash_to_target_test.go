//go:build testonly
// +build testonly

package tests

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// repeatingReader cycles through a 16-bit value pattern to fill any requested length.
type repeatingReader struct{ vals []uint16 }

func (r repeatingReader) Read(p []byte) (int, error) {
	if len(r.vals) == 0 {
		return 0, io.EOF
	}
	// fill p with little-endian u16 repeating
	// ensure even length
	n := len(p)
	if n%2 == 1 {
		n--
	}
	idx := 0
	for i := 0; i < n; i += 2 {
		v := r.vals[idx%len(r.vals)]
		binary.LittleEndian.PutUint16(p[i:i+2], v)
		idx++
	}
	if n < len(p) {
		p[n] = 0
	}
	return len(p), nil
}

func TestHashToTarget_16bitRejectionParity(t *testing.T) {
	// Q = 12289, N = 4
	par, _ := ntru.NewParams(4, big.NewInt(12289))
	// pattern: include values >= Q_MULT16 (=61445) for rejection, and accepted values
	// Q_MULT16 = floor(2^16 / 12289)*12289 = 5*12289 = 61445
	// Accepted sequence (first 4): 61444 -> 12288, 100 -> 100, 0 -> 0, 12289 -> 0
	rr := repeatingReader{vals: []uint16{65535, 61445, 61444, 100, 0, 61445, 12289}}
	poly := ntru.PublicHashToTargetFromXOF(rr, par)
	got := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		got[i] = poly.Coeffs[i].Int64()
	}
	want := []int64{12288, 100, 0, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("coeff %d: got %d want %d", i, got[i], want[i])
		}
	}
}

func TestHashToTarget_SHAKEConsistency(t *testing.T) {
	// Ensure PublicHashToTarget equals the XOF-injected version when using SHAKE128(salt||msg).
	par, _ := ntru.NewParams(8, big.NewInt(12289))
	msg := []byte("test-msg")
	salt := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes
	p1 := ntru.PublicHashToTarget(msg, salt, par)
	h := sha3.NewShake128()
	h.Write(salt)
	h.Write(msg)
	p2 := ntru.PublicHashToTargetFromXOF(h, par)
	for i := 0; i < par.N; i++ {
		if p1.Coeffs[i].Cmp(p2.Coeffs[i]) != 0 {
			t.Fatalf("mismatch at %d", i)
		}
	}
	// Sanity: coefficients are in [0,Q)
	for i := 0; i < par.N; i++ {
		if p1.Coeffs[i].Sign() < 0 || p1.Coeffs[i].Cmp(par.Q) >= 0 {
			t.Fatalf("out of range coeff at %d", i)
		}
	}
	_ = bytes.MinRead // silence unused import if build changes
}
