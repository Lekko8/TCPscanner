//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

// Windows socket error numbers. The syscall package exposes only a few of the
// WSA* constants, so the values are listed explicitly. They are stable Win32
// definitions from WinSock2.h.
const (
	wsaECONNABORTED syscall.Errno = 10053
	wsaECONNRESET   syscall.Errno = 10054
	wsaETIMEDOUT    syscall.Errno = 10060
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
)

func stateFromErrno(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return StateError, false
	}

	switch errno {
	case wsaECONNREFUSED, wsaECONNRESET, wsaECONNABORTED:
		return StateClosed, true
	case wsaETIMEDOUT:
		return StateTimeout, true
	case wsaEHOSTUNREACH, wsaENETUNREACH, wsaEHOSTDOWN, wsaENETDOWN:
		return StateUnreachable, true
	default:
		return StateError, false
	}
}
