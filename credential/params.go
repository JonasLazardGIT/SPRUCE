package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vSIS-Signature/commitment"
	"vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Params captures the public inputs required during issuance.
type Params struct {
	Ac     commitment.Matrix
	BPath  string
	AcPath string
	BoundB int64
	LenM1  int
	LenM2  int
	LenRU0 int
	LenRU1 int
	LenR   int
	RingQ  *ring.Ring
}

// paramsFile mirrors the JSON schema stored on disk.
type paramsFile struct {
	AcPath string `json:"AcPath"`
	BPath  string `json:"BPath"`
	BoundB int64  `json:"BoundB"`
	LenM1  int    `json:"LenM1"`
	LenM2  int    `json:"LenM2"`
	LenRU0 int    `json:"LenRU0"`
	LenRU1 int    `json:"LenRU1"`
	LenR   int    `json:"LenR"`
}

// LoadParamsFromFile reads the credential parameters JSON and materialises Ac in
// NTT form using the default ring (Parameters/Parameters.json).
//
// Expected Ac JSON schema (coeff-domain):
// { "Ac": [ [ [c00, c01, ...], [c01, ...] ], ... ] }
// i.e. Ac[row][col][coeff] with all rows having the same column count and all
// polynomials of length N. Polys are lifted to NTT internally.
func LoadParamsFromFile(path string) (*Params, error) {
	ringQ, err := LoadDefaultRing()
	if err != nil {
		return nil, err
	}
	return loadParamsInternal(path, ringQ)
}

func loadParamsInternal(path string, ringQ *ring.Ring) (*Params, error) {
	raw, resolved, err := readFileWithFallback(path)
	if err != nil {
		return nil, err
	}
	var pf paramsFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("parse params: %w", err)
	}
	if pf.BPath == "" {
		pf.BPath = "Parameters/Bmatrix.json"
	}
	if pf.BoundB == 0 {
		return nil, fmt.Errorf("params: BoundB must be non-zero")
	}
	if pf.LenM1 < 0 || pf.LenM2 < 0 || pf.LenRU0 < 0 || pf.LenRU1 < 0 || pf.LenR < 0 {
		return nil, fmt.Errorf("params: lengths must be non-negative")
	}
	acPath := pf.AcPath
	if acPath == "" {
		return nil, fmt.Errorf("params: AcPath required")
	}
	if !filepath.IsAbs(acPath) {
		acPath = filepath.Join(filepath.Dir(resolved), acPath)
	}
	acMat, err := loadAc(acPath, ringQ)
	if err != nil {
		return nil, fmt.Errorf("load Ac: %w", err)
	}
	expectedCols := pf.LenM1 + pf.LenM2 + pf.LenRU0 + pf.LenRU1 + pf.LenR
	if expectedCols == 0 {
		return nil, fmt.Errorf("params: expectedCols is zero")
	}
	if len(acMat) == 0 || len(acMat[0]) != expectedCols {
		return nil, fmt.Errorf("params: Ac columns=%d, expected=%d", len(acMat[0]), expectedCols)
	}
	return &Params{
		Ac:     acMat,
		BPath:  pf.BPath,
		AcPath: acPath,
		BoundB: pf.BoundB,
		LenM1:  pf.LenM1,
		LenM2:  pf.LenM2,
		LenRU0: pf.LenRU0,
		LenRU1: pf.LenRU1,
		LenR:   pf.LenR,
		RingQ:  ringQ,
	}, nil
}

func readFileWithFallback(path string) ([]byte, string, error) {
	candidates := []string{path}
	if !filepath.IsAbs(path) {
		candidates = append(candidates, filepath.Join("..", path), filepath.Join("..", "..", path))
	}
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			return data, p, nil
		}
	}
	return nil, "", fmt.Errorf("read %s: not found", path)
}

// loadAc parses Ac from JSON and lifts each polynomial to NTT.
func loadAc(path string, ringQ *ring.Ring) (commitment.Matrix, error) {
	type acJSON struct {
		Ac [][][]uint64 `json:"Ac"`
	}
	data, _, err := readFileWithFallback(path)
	if err != nil {
		return nil, err
	}
	var aj acJSON
	if err := json.Unmarshal(data, &aj); err != nil {
		return nil, fmt.Errorf("parse Ac: %w", err)
	}
	if len(aj.Ac) == 0 {
		return nil, fmt.Errorf("Ac: empty matrix")
	}
	rows := len(aj.Ac)
	cols := len(aj.Ac[0])
	mat := make(commitment.Matrix, rows)
	for i := 0; i < rows; i++ {
		if len(aj.Ac[i]) != cols {
			return nil, fmt.Errorf("Ac: ragged row %d", i)
		}
		mat[i] = make([]*ring.Poly, cols)
		for j := 0; j < cols; j++ {
			if len(aj.Ac[i][j]) != ringQ.N {
				return nil, fmt.Errorf("Ac: row %d col %d len=%d want=%d", i, j, len(aj.Ac[i][j]), ringQ.N)
			}
			p := ringQ.NewPoly()
			copy(p.Coeffs[0], aj.Ac[i][j])
			ringQ.NTT(p, p)
			mat[i][j] = p
		}
	}
	return mat, nil
}

// LoadDefaultRing constructs the ring from Parameters/Parameters.json with
// fallback to parent directories (shared helper for params loading).
func LoadDefaultRing() (*ring.Ring, error) {
	par, err := io.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		if parUp, errUp := io.LoadParams("../Parameters/Parameters.json", true); errUp == nil {
			par = parUp
		} else if parUp2, errUp2 := io.LoadParams("../../Parameters/Parameters.json", true); errUp2 == nil {
			par = parUp2
		} else {
			return nil, err
		}
	}
	return ring.NewRing(par.N, []uint64{par.Q})
}
