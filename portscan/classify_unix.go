//go:build !windows

package portscan

import "syscall"

func errnoState(errno syscall.Errno) State {
	switch errno {
	case syscall.ECONNREFUSED, syscall.ECONNRESET:
		return StateClosed
	case syscall.ETIMEDOUT:
		return StateTimeout
	case syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENETDOWN:
		return StateUnreachable
	default:
		return StateError
	}
}
