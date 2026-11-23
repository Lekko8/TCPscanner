//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !illumos

package portscan

// stateFromErrno is a no-op on platforms that do not expose syscall.Errno.
// Connect failures are still classified through net.Error and context errors.
func stateFromErrno(error) (State, bool) {
	return StateError, false
}
