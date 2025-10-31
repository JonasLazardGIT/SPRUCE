package PIOP

import (
	"os"
	"path/filepath"
)

// resolve returns path if it exists, otherwise tries the same path
// relative to the parent directory. This allows running from the
// module root or from within the PIOP subdirectory.
func resolve(rel string) string {
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	return filepath.Join("..", rel)
}
