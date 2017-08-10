package circuit

import (
	"sync"
)

// CircuitTableMarker marks a CircuitTable in a Zoo.
var CircuitTableMarker = &struct{ circuitTableMarker uint32 }{}

// CircuitTable manages Circuits for a peer.
type CircuitTable struct {
	// tableMtx locks when modifying the table
	tableMtx sync.Mutex
}

// NewCircuitTable builds a new CircuitTable.
func NewCircuitTable() *CircuitTable {
	return nil
}
