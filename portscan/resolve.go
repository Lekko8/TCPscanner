package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// lookupResolver is the part of *net.Resolver used by Scanner. It is an
// interface to keep the scanner testable without touching the network.
type lookupResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolvedTarget is the result of resolving one scan target.
type resolvedTarget struct {
	host  string
	addrs []netip.Addr
	err   error
}

// resolveAll resolves DNS targets concurrently with the same concurrency limit
// as the connect phase. Literal IP targets are not sent to the resolver.
func (s *Scanner) resolveAll(ctx context.Context, targets []target) []resolvedTarget {
	resolved := make([]resolvedTarget, len(targets))

	pending := 0
	for i, t := range targets {
		if t.isLiteral() {
			resolved[i] = resolvedTarget{host: t.host, addrs: []netip.Addr{t.addr}}
			continue
		}
		pending++
	}
	if pending == 0 {
		return resolved
	}

	work := make(chan int)
	workers := min(s.concurrency, pending)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for index := range work {
				t := targets[index]
				resolved[index] = s.resolveTarget(ctx, t)
			}
		}()
	}

feed:
	for i, t := range targets {
		if t.isLiteral() {
			continue
		}
		select {
		case work <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()

	return resolved
}

func (s *Scanner) resolveTarget(ctx context.Context, t target) resolvedTarget {
	addrs, err := s.resolver.LookupNetIP(ctx, "ip", t.name)
	if err != nil {
		return resolvedTarget{host: t.host, err: err}
	}

	unique := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]struct{}, len(addrs))
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, addr)
	}

	if len(unique) == 0 {
		return resolvedTarget{
			host: t.host,
			err:  fmt.Errorf("%w: %q", ErrNoAddresses, t.host),
		}
	}

	return resolvedTarget{host: t.host, addrs: unique}
}

var _ lookupResolver = (*net.Resolver)(nil)
