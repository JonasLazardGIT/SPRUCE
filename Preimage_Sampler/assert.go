package Preimage_Sampler

import "log"

// doStatCheck enables the statistical covariance check when sampler_debug is set.
var doStatCheck bool

func assert(cond bool, msg string, args ...any) {
	if samplerDebug && !cond {
		log.Fatalf(msg, args...)
	}
}

const samplerDebug = false
