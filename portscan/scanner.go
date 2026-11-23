package portscan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Scanner performs TCP connect scans. A Scanner is immutable after creation
// and is safe for concurrent use by multiple goroutines, including concurrent
// Scan calls.
//
// The zero value is ready to use and is equivalent to New() with default
// options. New is the preferred constructor because it allows configuring the
// concurrency and timeout and reports invalid options as errors.
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	resolver       lookupResolver
	dial           dialFunc
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// New creates a Scanner with the given options.
//
// The default configuration uses 100 concurrent connection attempts and a
// 5 second connect timeout. Invalid option values are reported as
// ErrInvalidOption.
func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
	}

	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: option %d is nil", ErrInvalidOption, i)
		}
		if err := opt.apply(&cfg); err != nil {
			return nil, err
		}
	}

	dialer := &net.Dialer{Timeout: cfg.connectTimeout}

	return &Scanner{
		concurrency:    cfg.concurrency,
		connectTimeout: cfg.connectTimeout,
		resolver:       net.DefaultResolver,
		dial:           dialer.DialContext,
	}, nil
}

// Scan checks the given TCP ports on the given hosts.
//
// Hosts may be IPv4 literals, IPv6 literals (with or without brackets) or
// DNS names. A DNS name is resolved to all of its addresses, and one result is
// produced for every address and port. Duplicate hosts are ignored: literals
// are compared by canonical address, DNS names case-insensitively, ignoring a
// trailing dot. CIDR notation is not supported.
//
// Invalid input is reported synchronously: ErrNoHosts, ErrInvalidHost,
// ErrNoPorts, ErrInvalidPort or ErrInvalidPortRange. A DNS name that cannot be
// resolved does not fail the whole scan; instead, every requested port for
// that host is reported with StateError and the resolver error in Result.Err.
//
// The returned channel is closed when the scan is done. Results are delivered
// in completion order. A single scan performs at most the configured number of
// concurrent connect attempts. Scan itself does not modify the Scanner, so one
// instance may be reused and used concurrently.
//
// The caller must drain the result channel or cancel ctx. If the caller stops
// reading without canceling, worker goroutines block on delivery; this is
// intentional backpressure, and memory usage stays bounded. After ctx is
// canceled, no new probes are started, in-flight probes are canceled, and the
// channel is closed once those probes have finished. Results for probes that
// were never started are not produced, and delivery of canceled results is
// best effort.
//
// If ctx is already canceled, Scan returns the context error without starting
// a scan.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if s == nil {
		return nil, ErrNilScanner
	}
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Work on a copy so that the zero value is usable and Scan never mutates
	// the receiver. A Scanner built by New is already fully initialized.
	scanner := *s
	if scanner.concurrency <= 0 {
		scanner.concurrency = defaultConcurrency
	}
	if scanner.connectTimeout <= 0 {
		scanner.connectTimeout = defaultConnectTimeout
	}
	if scanner.resolver == nil {
		scanner.resolver = net.DefaultResolver
	}
	if scanner.dial == nil {
		dialer := &net.Dialer{Timeout: scanner.connectTimeout}
		scanner.dial = dialer.DialContext
	}

	targets, err := parseTargets(hosts)
	if err != nil {
		return nil, err
	}
	portList, err := ports.expand()
	if err != nil {
		return nil, err
	}

	results := make(chan Result, scanner.concurrency)
	go scanner.run(ctx, targets, portList, results)

	return results, nil
}
