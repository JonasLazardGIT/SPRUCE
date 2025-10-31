package keys

import (
	"encoding/json"
	"os"
)

// PublicKey represents an NTRU public key persisted to JSON.
type PublicKey struct {
	Version string  `json:"version"`
	N       int     `json:"N"`
	Q       string  `json:"Q"`
	HCoeffs []int64 `json:"h_coeffs"`
}

// SavePublic writes the public key to ./ntru_keys/public.json.
func SavePublic(pk *PublicKey) error {
	if pk == nil {
		return nil
	}
	if err := os.MkdirAll("ntru_keys", 0o755); err != nil {
		return err
	}
	f, err := os.Create("ntru_keys/public.json")
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(pk)
}

// LoadPublic reads the public key from ./ntru_keys/public.json.
func LoadPublic() (*PublicKey, error) {
	data, err := os.ReadFile("ntru_keys/public.json")
	if err != nil {
		return nil, err
	}
	var pk PublicKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}
