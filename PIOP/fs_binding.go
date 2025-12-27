package PIOP

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PublicLabel binds a public name to an encoded byte slice for FS.
type PublicLabel struct {
	Name string
	Data []byte
}

// BuildPublicLabels assembles public inputs in a deterministic order suitable
// for FS binding.
func BuildPublicLabels(pub PublicInputs) []PublicLabel {
	var labels []PublicLabel
	appendPoly := func(name string, polys []*ring.Poly) {
		if len(polys) == 0 {
			return
		}
		buf := new(bytes.Buffer)
		for _, p := range polys {
			for _, c := range p.Coeffs[0] {
				_ = binary.Write(buf, binary.LittleEndian, c)
			}
		}
		labels = append(labels, PublicLabel{Name: name, Data: buf.Bytes()})
	}
	appendInt64 := func(name string, vals []int64) {
		if len(vals) == 0 {
			return
		}
		b := make([]byte, 8*len(vals))
		for i, v := range vals {
			binary.LittleEndian.PutUint64(b[8*i:8*(i+1)], uint64(v))
		}
		labels = append(labels, PublicLabel{Name: name, Data: b})
	}
	appendInt64Slices := func(name string, slices [][]int64) {
		if len(slices) == 0 {
			return
		}
		buf := new(bytes.Buffer)
		for _, vals := range slices {
			for _, v := range vals {
				_ = binary.Write(buf, binary.LittleEndian, uint64(v))
			}
		}
		labels = append(labels, PublicLabel{Name: name, Data: buf.Bytes()})
	}
	if len(pub.Com) > 0 {
		appendPoly("Com", pub.Com)
	}
	if len(pub.RI0) > 0 {
		appendPoly("RI0", pub.RI0)
	}
	if len(pub.RI1) > 0 {
		appendPoly("RI1", pub.RI1)
	}
	if len(pub.Ac) > 0 {
		flat := make([]*ring.Poly, 0, len(pub.Ac)*len(pub.Ac[0]))
		for _, row := range pub.Ac {
			flat = append(flat, row...)
		}
		appendPoly("Ac", flat)
	}
	if len(pub.A) > 0 {
		flat := make([]*ring.Poly, 0, len(pub.A)*len(pub.A[0]))
		for _, row := range pub.A {
			flat = append(flat, row...)
		}
		appendPoly("A", flat)
	}
	if len(pub.B) > 0 {
		appendPoly("B", pub.B)
	}
	if len(pub.T) > 0 {
		appendInt64("T", pub.T)
	}
	if len(pub.Tag) > 0 {
		appendInt64Slices("Tag", pub.Tag)
	}
	if len(pub.Nonce) > 0 {
		appendInt64Slices("Nonce", pub.Nonce)
	}
	if len(pub.U) > 0 {
		appendPoly("U", pub.U)
	}
	if len(pub.Extras) > 0 {
		keys := make([]string, 0, len(pub.Extras))
		for k := range pub.Extras {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if b, ok := pub.Extras[k].([]byte); ok {
				labels = append(labels, PublicLabel{Name: k, Data: b})
			}
		}
	}
	return labels
}
