package keys

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	measure "vSIS-Signature/measure"
)

// Signature holds the signature bundle persisted to JSON.
type Signature struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Params    struct {
		N int    `json:"N"`
		Q string `json:"Q"`
	} `json:"params"`
	Hash struct {
		BFile   string  `json:"B_file"`
		MSeed   string  `json:"mseed"`
		X0Seed  string  `json:"x0seed"`
		X1Seed  string  `json:"x1seed"`
		TCoeffs []int64 `json:"t_coeffs"`
	} `json:"hash"`
	PublicKey struct {
		HCoeffs []int64 `json:"h_coeffs"`
	} `json:"public_key"`
	Signature struct {
		S0   []int64 `json:"s0"`
		S1   []int64 `json:"s1"`
		S2   []int64 `json:"s2"`
		Norm struct {
			Passed       bool    `json:"passed"`
			L2Est        float64 `json:"l2_est"`
			ResidualLinf int64   `json:"residual_linf,omitempty"`
		} `json:"norm"`
		TrialsUsed int  `json:"trials_used"`
		Rejected   bool `json:"rejected"`
		MaxTrials  int  `json:"max_trials"`
	} `json:"signature"`
}

// NewSignature creates a base signature with timestamp.
func NewSignature() *Signature {
	s := &Signature{Version: "ntru-signature-v1"}
	s.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return s
}

// Save writes signature to ./ntru_keys/signature.json.
func Save(sig *Signature) error {
	if sig == nil {
		return nil
	}
	if err := os.MkdirAll("ntru_keys", 0o755); err != nil {
		return err
	}
	f, err := os.Create("ntru_keys/signature.json")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sig); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if measure.Enabled {
		if info, err := os.Stat("ntru_keys/signature.json"); err == nil {
			measure.Global.Add("ntru/signature/json_file", info.Size())
		}
	}
	return nil
}

// Load reads signature from ./ntru_keys/signature.json.
func Load() (*Signature, error) {
	data, err := os.ReadFile("ntru_keys/signature.json")
	if err != nil {
		return nil, err
	}
	var sig Signature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// DecodeSeed converts base64 seed string to bytes.
func DecodeSeed(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodeSeed returns base64 representation of seed bytes.
func EncodeSeed(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
