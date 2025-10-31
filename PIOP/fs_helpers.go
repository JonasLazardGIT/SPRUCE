package PIOP

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// XOF models the extendable-output function used by the Fiat–Shamir layer.
type XOF interface {
	Expand(label string, parts ...[]byte) []byte
}

// Shake256XOF is a SHAKE-256 backed implementation of XOF with a fixed output length.
type Shake256XOF struct {
	outLen int
}

// NewShake256XOF returns a SHAKE-256 XOF that emits outLen bytes on every squeeze.
func NewShake256XOF(outLen int) Shake256XOF {
	if outLen <= 0 {
		panic("NewShake256XOF: outLen must be > 0")
	}
	return Shake256XOF{outLen: outLen}
}

// Expand realises the SHAKE-256 duplex keyed by `label` and concatenates `parts`.
func (s Shake256XOF) Expand(label string, parts ...[]byte) []byte {
	h := sha3.NewShake256()
	if _, err := h.Write([]byte(label)); err != nil {
		panic(fmt.Errorf("Shake256XOF: write label: %w", err))
	}
	for _, p := range parts {
		if _, err := h.Write(p); err != nil {
			panic(fmt.Errorf("Shake256XOF: write payload: %w", err))
		}
	}
	out := make([]byte, s.outLen)
	if _, err := h.Read(out); err != nil {
		panic(fmt.Errorf("Shake256XOF: read output: %w", err))
	}
	return out
}

// FSParams bundles the Fiat–Shamir security parameters.
type FSParams struct {
	Lambda int // random oracle security parameter (bits)
	Kappa  [4]int
}

// FS tracks the four grinding rounds in the SmallWood–ARK transcript.
type FS struct {
	xof    XOF
	params FSParams
	salt   []byte
	ctr    [4]uint64
	h      [4][]byte
	labels [4]string
}

// NewFS prepares the Fiat–Shamir state with the provided XOF and salt.
func NewFS(x XOF, salt []byte, params FSParams) *FS {
	if params.Lambda <= 0 {
		params.Lambda = 256
	}
	fs := &FS{
		xof:    x,
		params: params,
		salt:   append([]byte(nil), salt...),
		labels: [4]string{"fs-gamma", "fs-gammap", "fs-eprime", "fs-tail"},
	}
	return fs
}

// Salt returns a defensive copy of the Fiat–Shamir salt.
func (fs *FS) Salt() []byte {
	return append([]byte(nil), fs.salt...)
}

// Ctr exposes the grinding counter recorded for the given round.
func (fs *FS) Ctr(round int) uint64 {
	if round < 0 || round >= len(fs.ctr) {
		panic("FS.Ctr: round out of range")
	}
	return fs.ctr[round]
}

// GrindAndDerive performs the κ-bit grinding loop for the selected round and
// returns the accepted hash material along with the derived challenge bytes.
func (fs *FS) GrindAndDerive(round int, material [][]byte, derive func([]byte) []byte) (h []byte, ctr uint64, chal []byte) {
	if round < 0 || round >= len(fs.ctr) {
		panic("FS.GrindAndDerive: round out of range")
	}
	kappa := fs.params.Kappa[round]
	counter := fs.ctr[round]
	for {
		input := make([]byte, len(fs.salt))
		copy(input, fs.salt)
		for _, m := range material {
			input = append(input, m...)
		}
		input = append(input, u64le(counter)...)
		digest := fs.xof.Expand(fs.labels[round], input)
		if hasZeroPrefix(digest, kappa) {
			fs.h[round] = append([]byte(nil), digest...)
			fs.ctr[round] = counter
			chal = derive(digest)
			return fs.h[round], counter, chal
		}
		counter++
		if counter == 0 {
			panic("FS.GrindAndDerive: counter wrapped")
		}
	}
}

// hasZeroPrefix checks whether the first kappa bits of buf are zero.
func hasZeroPrefix(buf []byte, kappa int) bool {
	if kappa <= 0 {
		return true
	}
	needed := (kappa + 7) / 8
	if len(buf) < needed {
		return false
	}
	full := kappa / 8
	for i := 0; i < full; i++ {
		if buf[i] != 0 {
			return false
		}
	}
	rem := kappa % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xFF << (8 - rem))
	return buf[full]&mask == 0
}

func u64le(v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return buf[:]
}
