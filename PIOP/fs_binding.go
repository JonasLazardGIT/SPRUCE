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
	if len(pub.B) > 0 {
		appendPoly("B", pub.B)
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
