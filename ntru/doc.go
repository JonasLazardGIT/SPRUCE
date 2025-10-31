package ntru

// Package ntru implements NTRU lattice trapdoors, sampling and
// signature primitives in pure Go. It mirrors the reference C
// implementation in ntru_c while exposing a Go friendly API for
// key generation, preimage sampling and signing.
//
// The code focuses on bit-for-bit compatibility with the reference
// while providing clear abstractions for polynomials, ring arithmetic
// and sampling routines used by the vSIS signature scheme.
