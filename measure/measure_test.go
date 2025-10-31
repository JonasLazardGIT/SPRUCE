package measure

import (
	"math/big"
	"testing"
)

func TestBytesField(t *testing.T) {
	q := big.NewInt(17)
	if got := BytesField(q); got != 1 {
		t.Fatalf("BytesField(17)=%d want 1", got)
	}
	q.SetUint64(256)
	if got := BytesField(q); got != 2 {
		t.Fatalf("BytesField(256)=%d want 2", got)
	}
}

func TestBytesPolyDegree(t *testing.T) {
	if got := BytesPolyDegree(3, 1); got != 4 {
		t.Fatalf("BytesPolyDegree(3,1)=%d want 4", got)
	}
	if got := BytesPolyDegree(5, 2); got != 12 {
		t.Fatalf("BytesPolyDegree(5,2)=%d want 12", got)
	}
}
