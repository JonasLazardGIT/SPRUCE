package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// commitRows wraps LVCS.CommitInitWithParams and layout assignment, mirroring
// the behaviour in buildSimWith for a given set of rows and ell.
func commitRows(ringQ *ring.Ring, rows []lvcs.RowInput, ell int, decsParams decs.Params, witnessCount, maskOffset, maskCount int) (root [16]byte, pk *lvcs.ProverKey, oracleLayout lvcs.OracleLayout, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	if len(rows) == 0 {
		err = fmt.Errorf("no rows to commit")
		return
	}
	root, pk, err = lvcs.CommitInitWithParams(ringQ, rows, ell, decsParams)
	if err != nil {
		return
	}
	oracleLayout.Witness = lvcs.LayoutSegment{Offset: 0, Count: witnessCount}
	oracleLayout.Mask = lvcs.LayoutSegment{Offset: maskOffset, Count: maskCount}
	if err = pk.SetLayout(oracleLayout); err != nil {
		return
	}
	return
}
