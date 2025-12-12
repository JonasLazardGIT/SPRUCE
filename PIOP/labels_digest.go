package PIOP

import (
	"crypto/sha256"
	"encoding/binary"
)

// computeLabelsDigest hashes the list of public labels to a fixed digest.
func computeLabelsDigest(labels []PublicLabel) []byte {
	h := sha256.New()
	for _, l := range labels {
		// Encode name length + name bytes + data length + data bytes.
		binary.Write(h, binary.LittleEndian, uint32(len(l.Name)))
		h.Write([]byte(l.Name))
		binary.Write(h, binary.LittleEndian, uint32(len(l.Data)))
		h.Write(l.Data)
	}
	return h.Sum(nil)
}
