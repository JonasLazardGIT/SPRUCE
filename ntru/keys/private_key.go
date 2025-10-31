package keys

import (
	"encoding/json"
	"os"
)

// PrivateKey represents an NTRU private key persisted to JSON.
type PrivateKey struct {
	Version string  `json:"version"`
	N       int     `json:"N"`
	Q       string  `json:"Q"`
	F       []int64 `json:"F"`
	G       []int64 `json:"G"`
	Fsmall  []int64 `json:"f"`
	Gsmall  []int64 `json:"g"`
	Policy  *struct {
		FPlus      int    `json:"f_plus"`
		FMinus     int    `json:"f_minus"`
		GPlus      int    `json:"g_plus"`
		GMinus     int    `json:"g_minus"`
		SeedHex    string `json:"seed,omitempty"`
		TrialsUsed int    `json:"trials_used"`
	} `json:"policy,omitempty"`
}

// SavePrivate writes the private key to ./ntru_keys/private.json.
func SavePrivate(sk *PrivateKey) error {
	if sk == nil {
		return nil
	}
	if err := os.MkdirAll("ntru_keys", 0o755); err != nil {
		return err
	}
	f, err := os.Create("ntru_keys/private.json")
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(sk)
}

// LoadPrivate reads the private key from ./ntru_keys/private.json.
func LoadPrivate() (*PrivateKey, error) {
	data, err := os.ReadFile("ntru_keys/private.json")
	if err != nil {
		return nil, err
	}
	var sk PrivateKey
	if err := json.Unmarshal(data, &sk); err != nil {
		return nil, err
	}
	return &sk, nil
}
