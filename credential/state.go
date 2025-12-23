package credential

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// State captures all holder-side data needed to persist a credential.
// All polys are stored in coefficient form (no seeds).
type State struct {
	M1  [][]int64 `json:"m1"`
	M2  [][]int64 `json:"m2"`
	RU0 [][]int64 `json:"ru0"`
	RU1 [][]int64 `json:"ru1"`
	R   [][]int64 `json:"r"`
	R0  [][]int64 `json:"r0"`
	R1  [][]int64 `json:"r1"`
	// Optional carry rows if used.
	K0 [][]int64 `json:"k0,omitempty"`
	K1 [][]int64 `json:"k1,omitempty"`
	// Hash target and signature preimage.
	T   []int64   `json:"t"`
	U   []int64   `json:"u"`
	Com [][]int64 `json:"com"`
	RI0 [][]int64 `json:"ri0"`
	RI1 [][]int64 `json:"ri1"`
	// Paths to public parameters.
	BPath  string `json:"b_path"`
	AcPath string `json:"ac_path"`
	// Embedded public parameters (coeff domain) for portability.
	B  [][]int64   `json:"b,omitempty"`
	Ac [][][]int64 `json:"ac,omitempty"`
	// NTRU keys (coeff form).
	NTRUPublic  [][]int64 `json:"ntru_public,omitempty"`
	NTRUPrivate [][]int64 `json:"ntru_private,omitempty"`
}

// polyToInt64 converts a ring.Poly to coeff slice in [-q/2, q/2].
func polyToInt64(p *ring.Poly, ringQ *ring.Ring) []int64 {
	out := make([]int64, ringQ.N)
	q := int64(ringQ.Modulus[0])
	half := q / 2
	for i, c := range p.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out
}

// polysToInt64 converts a slice of polys.
func polysToInt64(vec []*ring.Poly, ringQ *ring.Ring) [][]int64 {
	out := make([][]int64, len(vec))
	for i, p := range vec {
		out[i] = polyToInt64(p, ringQ)
	}
	return out
}

// polyFromInt64 builds a coeff-domain poly from centered coeffs in [-q/2,q/2].
func polyFromInt64(coeffs []int64, ringQ *ring.Ring) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i, v := range coeffs {
		val := v
		if val < 0 {
			val += q
		}
		p.Coeffs[0][i] = uint64(val % q)
	}
	return p
}

// polysFromInt64 builds a slice of polys from coeff slices.
func polysFromInt64(vec [][]int64, ringQ *ring.Ring) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i, coeffs := range vec {
		out[i] = polyFromInt64(coeffs, ringQ)
	}
	return out
}

// matrixToInt64 converts a matrix of polys (NTT or coeff) to coeff slices.
func matrixToInt64(mat [][]*ring.Poly, ringQ *ring.Ring, ntt bool) [][][]int64 {
	if len(mat) == 0 {
		return nil
	}
	rows := len(mat)
	cols := len(mat[0])
	out := make([][][]int64, rows)
	for i := 0; i < rows; i++ {
		out[i] = make([][]int64, cols)
		for j := 0; j < cols; j++ {
			p := mat[i][j]
			if ntt {
				cp := ringQ.NewPoly()
				ring.Copy(p, cp)
				ringQ.InvNTT(cp, cp)
				p = cp
			}
			out[i][j] = polyToInt64(p, ringQ)
		}
	}
	return out
}

// SaveState writes the credential state to the given path.
func SaveState(path string, ringQ *ring.Ring, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

// LoadState reads a credential state from disk.
func LoadState(path string) (State, error) {
	var st State
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("unmarshal state: %w", err)
	}
	return st, nil
}
