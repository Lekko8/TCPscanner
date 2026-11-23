package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// classifyConnectError converts a dial error into a structured state.
// Classification is based on error types and syscall error numbers; error
// strings are never inspected.
//
// Context cancellation takes precedence over the timeout returned by the
// dialer: if the caller's context is done, the result is StateCanceled.
func classifyConnectError(ctx context.Context, err error) (State, error) {
	if err == nil {
		return StateOpen, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return StateCanceled, ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return StateCanceled, err
	}
	if isTimeoutError(err) {
		return StateTimeout, err
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errnoState(errno) {
		case StateClosed:
			// A refused or reset connection is a probe outcome, not an
			// error. Err is nil for StateClosed.
			return StateClosed, nil
		case StateTimeout:
			return StateTimeout, err
		case StateUnreachable:
			return StateUnreachable, err
		}
	}

	return StateError, err
}

// classifyResolveError classifies an error returned while resolving a host
// name. Resolution failures are reported per requested port with StateError,
// except for cancellations and timeouts.
func classifyResolveError(ctx context.Context, err error) (State, error) {
	if err == nil {
		return StateError, ErrNoAddresses
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return StateCanceled, ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return StateCanceled, err
	}
	if isTimeoutError(err) {
		return StateTimeout, err
	}
	return StateError, err
}

func isTimeoutError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
