package portscan

import (
	"fmt"
	"slices"
)

// Ports describes a set of TCP ports. The zero value is empty and is rejected
// by Scan with ErrNoPorts.
//
// Ports is immutable once constructed and can be reused by any number of
// scans, including concurrent scans.
type Ports struct {
	ranges []portRange
}

type portRange struct {
	from int
	to   int // inclusive
}

// Range returns a set containing all ports from from to to inclusive. The
// arguments are ints rather than uint16 so that out-of-range values can be
// reported instead of silently wrapping around.
//
// A range is validated by Scan. Ports must be in 1..65535 and from must not be
// greater than to.
func Range(from, to int) Ports {
	return Ports{ranges: []portRange{{from: from, to: to}}}
}

// List returns a set containing the given ports. Ports may be repeated; the
// repetitions are removed when the set is expanded. Every port is validated by
// Scan and must be in 1..65535.
func List(ports ...int) Ports {
	ranges := make([]portRange, len(ports))
	for i, port := range ports {
		ranges[i] = portRange{from: port, to: port}
	}
	return Ports{ranges: ranges}
}

// Union returns the union of several port sets. Duplicates are removed when
// the set is expanded. Union without arguments returns an empty set.
func Union(sets ...Ports) Ports {
	var ranges []portRange
	for _, set := range sets {
		ranges = append(ranges, set.ranges...)
	}
	return Ports{ranges: ranges}
}

// expand validates the set and returns its ports in ascending order without
// duplicates.
func (p Ports) expand() ([]uint16, error) {
	if len(p.ranges) == 0 {
		return nil, ErrNoPorts
	}

	var seen [65536]bool
	ports := make([]uint16, 0, 64)

	for _, r := range p.ranges {
		if r.from < 1 || r.from > 65535 || r.to < 1 || r.to > 65535 {
			if r.from == r.to {
				return nil, fmt.Errorf("%w: port %d is outside 1..65535", ErrInvalidPort, r.from)
			}
			return nil, fmt.Errorf("%w: range %d-%d is outside 1..65535", ErrInvalidPort, r.from, r.to)
		}
		if r.from > r.to {
			return nil, fmt.Errorf("%w: %d-%d has a start greater than its end", ErrInvalidPortRange, r.from, r.to)
		}
		for port := r.from; port <= r.to; port++ {
			if seen[port] {
				continue
			}
			seen[port] = true
			ports = append(ports, uint16(port))
		}
	}

	slices.Sort(ports)
	return ports, nil
}
