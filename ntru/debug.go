package ntru

import (
	"fmt"
	"io"
	"os"
)

var debugOn = os.Getenv("NTRU_DEBUG") == "1"

func dbg(w io.Writer, f string, a ...any) {
    if debugOn {
        fmt.Fprintf(w, f, a...)
    }
}

func abs64(x int64) int64 { if x < 0 { return -x }; return x }
