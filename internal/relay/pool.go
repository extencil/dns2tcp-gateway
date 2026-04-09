package relay

import (
	"fmt"
	"sync"
)

// PortPool manages a pool of available TCP ports for RTCP sessions.
type PortPool struct {
	mu        sync.Mutex
	available []int
	allocated map[int]bool
}

// NewPortPool creates a port pool for the given range [min, max).
func NewPortPool(min, max int) *PortPool {
	available := make([]int, 0, max-min)
	for p := min; p < max; p++ {
		available = append(available, p)
	}

	return &PortPool{
		available: available,
		allocated: make(map[int]bool, max-min),
	}
}

// Allocate returns the next available port from the pool.
func (pp *PortPool) Allocate() (int, error) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	if len(pp.available) == 0 {
		return 0, fmt.Errorf("relay: no ports available")
	}

	port := pp.available[0]
	pp.available = pp.available[1:]
	pp.allocated[port] = true
	return port, nil
}

// Release returns a port back to the pool.
func (pp *PortPool) Release(port int) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	if !pp.allocated[port] {
		return
	}

	delete(pp.allocated, port)
	pp.available = append(pp.available, port)
}

// Available returns the number of ports available in the pool.
func (pp *PortPool) Available() int {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	return len(pp.available)
}
