package ntru

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	mrand "math/rand"
)

func init() {
	var seed int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &seed); err != nil {
		seed = time.Now().UnixNano()
	}
	mrand.Seed(seed)
}
