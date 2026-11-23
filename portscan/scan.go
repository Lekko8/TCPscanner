package portscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Result is the outcome of a single TCP connect attempt to one address and
// port.
type Result struct {
	// Host is the target as normalized by the scanner. DNS names are kept as
	// provided (after trimming surrounding whitespace); literal IP addresses
	// are returned in canonical form without brackets or an IPv4-mapped IPv6
	// prefix.
	Host string

	// IP is the address that was actually probed. It is nil when the host
	// could not be resolved.
	IP net.IP

	// Port is the probed port.
	Port uint16

	// State is the structured outcome of the attempt.
	State State

	// Duration is the time spent on the TCP connect attempt. It is zero when
	// no attempt was made, for example because name resolution failed.
	Duration time.Duration

	// Err is the underlying error for StateTimeout, StateUnreachable,
	// StateCanceled and StateError. It is nil for StateOpen and StateClosed:
	// an explicitly refused connection is a successful probe with a known
	// outcome, not a scanner error.
	//
	// Err is informative only. In particular, callers must use State, not
	// Err.Error(), to determine the outcome.
	Err error
}

type job struct {
	host string
	addr netip.Addr
	port uint16
}

// run resolves targets, probes all address/port pairs and closes the result
// channel. The result channel is closed only after every worker has stopped.
func (s *Scanner) run(ctx context.Context, targets []target, ports []uint16, results chan<- Result) {
	resolved := s.resolveAll(ctx, targets)

	jobs := make(chan job)
	total := 0
	for _, rt := range resolved {
		if rt.err == nil {
			total += len(rt.addrs) * len(ports)
		}
	}

	var wg sync.WaitGroup
	workers := min(s.concurrency, total)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	s.produce(ctx, resolved, ports, jobs, results)

	close(jobs)
	wg.Wait()
	close(results)
}

// produce converts resolved targets into connection jobs and emits results for
// targets that could not be resolved.
func (s *Scanner) produce(
	ctx context.Context,
	resolved []resolvedTarget,
	ports []uint16,
	jobs chan<- job,
	results chan<- Result,
) {
	if ctx.Err() != nil {
		return
	}

	for _, rt := range resolved {
		if rt.err != nil {
			state, resultErr := classifyResolveError(ctx, rt.err)
			for _, port := range ports {
				if !sendResult(ctx, results, Result{
					Host:  rt.host,
					Port:  port,
					State: state,
					Err:   resultErr,
				}) {
					return
				}
			}
			continue
		}

		for _, addr := range rt.addrs {
			for _, port := range ports {
				select {
				case jobs <- job{host: rt.host, addr: addr, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan job, results chan<- Result) {
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			if !sendResult(ctx, results, s.check(ctx, j)) {
				return
			}
		}
	}
}

func (s *Scanner) check(ctx context.Context, j job) Result {
	start := time.Now()
	address := net.JoinHostPort(j.addr.String(), strconv.Itoa(int(j.port)))
	conn, err := s.dial(ctx, "tcp", address)
	duration := time.Since(start)

	result := Result{
		Host:     j.host,
		IP:       net.IP(j.addr.AsSlice()),
		Port:     j.port,
		Duration: duration,
	}

	if err != nil {
		result.State, result.Err = classifyConnectError(ctx, err)
		return result
	}

	if conn != nil {
		_ = conn.Close()
	}
	result.State = StateOpen
	return result
}

func sendResult(ctx context.Context, results chan<- Result, r Result) bool {
	select {
	case results <- r:
		return true
	case <-ctx.Done():
		return false
	}
}
