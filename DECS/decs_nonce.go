package decs

// DeriveNonce deterministically reconstructs the nonce for the given leaf index
// using the commitment nonce seed. It returns a slice of length nonceBytes.
func DeriveNonce(seed []byte, idx int, nonceBytes int) []byte {
	return deriveNonce(seed, idx, nonceBytes)
}
