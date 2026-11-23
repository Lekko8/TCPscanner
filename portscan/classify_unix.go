//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || illumos

package portscan

import (
	"errors"
	"syscall"
)

func stateFromErrno(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return StateError, false
	}

	switch errno {
	case syscall.ECONNREFUSED, syscall.ECONNRESET:
		return StateClosed, true
	case syscall.ETIMEDOUT:
		return StateTimeout, true
	case syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENETDOWN:
		return StateUnreachable, true
	default:
		return StateError, false
	}
}
