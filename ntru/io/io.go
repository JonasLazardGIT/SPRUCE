package io

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// SystemParams is the minimal set used at runtime.
// Supports both capital and lowercase JSON field names for compatibility.
type SystemParams struct {
	N    int    `json:"N"`
	Q    uint64 `json:"Q"`
	Beta uint64 `json:"beta"`
}

// LoadParams reads Parameters/Parameters.json and enforces N/Q unless allowMismatch.
func LoadParams(path string, allowMismatch bool) (SystemParams, error) {
	var p SystemParams
	// compatible struct for current on-disk format (lowercase keys)
	var rawAny map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &rawAny); err != nil {
		return p, err
	}
	// read N
	if v, ok := rawAny["N"]; ok {
		if f, ok := v.(float64); ok {
			p.N = int(f)
		}
	} else if v, ok := rawAny["n"]; ok {
		if f, ok := v.(float64); ok {
			p.N = int(f)
		}
	}
	// read Q (may be number)
	if v, ok := rawAny["Q"]; ok {
		switch t := v.(type) {
		case float64:
			p.Q = uint64(t)
		case string:
			// accept hex or decimal string
			if q, err := parseQString(t); err == nil {
				p.Q = q
			} else {
				return p, err
			}
		}
	} else if v, ok := rawAny["q"]; ok {
		switch t := v.(type) {
		case float64:
			p.Q = uint64(t)
		case string:
			if q, err := parseQString(t); err == nil {
				p.Q = q
			} else {
				return p, err
			}
		}
	}
	// read Beta (optional – for norm gadgets)
	if v, ok := rawAny["beta"]; ok {
		if f, ok := v.(float64); ok {
			p.Beta = uint64(f)
		}
	}
	if p.N == 0 || p.Q == 0 {
		return p, fmt.Errorf("invalid or missing N/Q in %s", path)
	}
	if !allowMismatch {
		if p.N != 1024 {
			return p, fmt.Errorf("want N=1024, got %d", p.N)
		}
		// Enforce q=1038337 for N=1024
		if p.Q != 1038337 {
			return p, fmt.Errorf("unsupported Q=%d (expected 1038337)", p.Q)
		}
	}
	return p, nil
}

func parseQString(s string) (uint64, error) {
	// try hex without 0x prefix; accept with prefix too
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if x, err := hex.DecodeString(s); err == nil {
		var q uint64
		for _, b := range x {
			q = (q << 8) | uint64(b)
		}
		return q, nil
	}
	// fallback: parse as decimal number
	var dec uint64
	if err := json.Unmarshal([]byte(s), &dec); err == nil {
		return dec, nil
	}
	return 0, fmt.Errorf("invalid Q string: %q", s)
}

// LoadBMatrixCoeffs returns the 4×N slice in coefficient domain.
// Validates that B has exactly 4 polys and each has length 1024.
func LoadBMatrixCoeffs(path string) ([][]uint64, error) {
	var tmp struct {
		B [][]uint64 `json:"B"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return nil, err
	}
	if len(tmp.B) != 4 {
		return nil, fmt.Errorf("b has %d rows, want 4", len(tmp.B))
	}
	for i := range tmp.B {
		if len(tmp.B[i]) != 1024 {
			return nil, fmt.Errorf("b[%d] has length %d, want 1024", i, len(tmp.B[i]))
		}
	}
	return tmp.B, nil
}

// LoadPublicH returns h(x) coefficients (length 1024) from public.json.
func LoadPublicH(path string) ([]int64, error) {
	var tmp struct {
		N int     `json:"N"`
		Q any     `json:"Q"`
		H []int64 `json:"h_coeffs"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return nil, err
	}
	if tmp.N != 1024 {
		return nil, fmt.Errorf("public.N=%d, want 1024", tmp.N)
	}
	if len(tmp.H) != 1024 {
		return nil, fmt.Errorf("h len=%d, want 1024", len(tmp.H))
	}
	return tmp.H, nil
}

// SigBundle selects seeds and signature coefficient rows from signature.json.
type SigBundle struct {
	MSeed  []byte
	X0Seed []byte
	X1Seed []byte
	S0     []int64
	S1     []int64
	S2     []int64
	N      int
	Q      string // original representation (hex/decimal) as in JSON
}

// LoadSignatureBundle returns seeds and signature coefficient rows.
func LoadSignatureBundle(path string) (SigBundle, error) {
	var out SigBundle
	var tmp struct {
		Params struct {
			N int    `json:"N"`
			Q string `json:"Q"`
		} `json:"params"`
		Hash struct {
			MSeed  []byte `json:"mseed"`
			X0Seed []byte `json:"x0seed"`
			X1Seed []byte `json:"x1seed"`
		} `json:"hash"`
		Signature struct {
			S0 []int64 `json:"s0"`
			S1 []int64 `json:"s1"`
			S2 []int64 `json:"s2"`
		} `json:"signature"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return out, err
	}
	if tmp.Params.N != 1024 {
		return out, fmt.Errorf("signature.params.N=%d, want 1024", tmp.Params.N)
	}
	if len(tmp.Signature.S0) != 1024 || len(tmp.Signature.S1) != 1024 {
		return out, fmt.Errorf("signature rows must be length 1024")
	}
	if len(tmp.Signature.S2) != 0 && len(tmp.Signature.S2) != 1024 {
		return out, fmt.Errorf("signature.s2 must be length 1024 when present")
	}
	out.MSeed, out.X0Seed, out.X1Seed = tmp.Hash.MSeed, tmp.Hash.X0Seed, tmp.Hash.X1Seed
	out.S0, out.S1 = tmp.Signature.S0, tmp.Signature.S1
	out.S2 = tmp.Signature.S2
	out.N, out.Q = tmp.Params.N, tmp.Params.Q
	return out, nil
}
