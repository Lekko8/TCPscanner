//go:build windows || aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || illumos

package portscan

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestClassifyConnectErrorErrno(t *testing.T) {
	tests := []struct {
		name  string
		errno error
		want  State
	}{
		{name: "refused", errno: errnoRefused(), want: StateClosed},
		{name: "reset", errno: errnoReset(), want: StateClosed},
		{name: "timed out", errno: errnoTimeout(), want: StateTimeout},
		{name: "host unreachable", errno: errnoHostUnreach(), want: StateUnreachable},
		{name: "network unreachable", errno: errnoNetUnreach(), want: StateUnreachable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: tc.errno},
			}

			state, resultErr := classifyConnectError(context.Background(), wrapped)
			if state != tc.want {
				t.Fatalf("state = %s, want %s", state, tc.want)
			}
			if state == StateClosed {
				if resultErr != nil {
					t.Fatalf("Err = %v, want nil for closed state", resultErr)
				}
				return
			}
			if resultErr == nil {
				t.Fatal("Err = nil, want the underlying error")
			}
		})
	}
}
