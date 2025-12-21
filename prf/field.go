package prf

// Elem represents a field element modulo q.
type Elem uint64

// Field exposes basic arithmetic modulo q.
type Field struct {
	q uint64
}

// NewField constructs a Field with modulus q.
func NewField(q uint64) Field {
	return Field{q: q}
}

func (f Field) Q() uint64 { return f.q }

func (f Field) add(a, b Elem) Elem {
	v := uint64(a) + uint64(b)
	if v >= f.q {
		v -= f.q
	}
	return Elem(v)
}

func (f Field) sub(a, b Elem) Elem {
	va := uint64(a)
	vb := uint64(b)
	if va >= vb {
		return Elem(va - vb)
	}
	return Elem(va + f.q - vb)
}

func (f Field) mul(a, b Elem) Elem {
	return Elem((uint64(a) * uint64(b)) % f.q)
}

// powSmall raises a to the small exponent d (suitable for Poseidon S-box).
func (f Field) powSmall(a Elem, d uint64) Elem {
	// binary exponentiation
	base := a
	var res Elem = 1
	exp := d
	for exp > 0 {
		if exp&1 == 1 {
			res = f.mul(res, base)
		}
		base = f.mul(base, base)
		exp >>= 1
	}
	return res
}
