package portscan

import (
	"fmt"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = 5 * time.Second
)

// Option configures a Scanner. Options are created by the With* functions.
// The interface intentionally has an unexported method, so only options
// provided by this package can be used.
type Option interface {
	apply(*config) error
}

type config struct {
	concurrency    int
	connectTimeout time.Duration
}

type optionFunc func(*config) error

func (f optionFunc) apply(cfg *config) error { return f(cfg) }

// WithConcurrency sets the maximum number of TCP connection attempts that a
// single Scan call performs at the same time. The value must be positive.
//
// The limit covers both DNS resolution and connect probing; those phases do
// not overlap, so the total number of concurrent network operations never
// exceeds n.
func WithConcurrency(n int) Option {
	return optionFunc(func(cfg *config) error {
		if n <= 0 {
			return fmt.Errorf("%w: concurrency must be positive, got %d", ErrInvalidOption, n)
		}
		cfg.concurrency = n
		return nil
	})
}

// WithConnectTimeout sets the timeout of a single TCP connect attempt. The
// value must be positive.
//
// The timeout applies to the TCP handshake only. DNS resolution is bounded by
// the context passed to Scan and by the system resolver. If the scan context
// expires earlier than the connect timeout, the attempt is reported as
// StateCanceled rather than StateTimeout.
func WithConnectTimeout(d time.Duration) Option {
	return optionFunc(func(cfg *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be positive, got %s", ErrInvalidOption, d)
		}
		cfg.connectTimeout = d
		return nil
	})
}
