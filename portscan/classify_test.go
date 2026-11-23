package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "test timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

func TestClassifyConnectError(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name      string
		ctx       context.Context
		err       error
		want      State
		wantErr   bool  // whether Result.Err must be non-nil
		wantErrIs error // if non-nil, checked with errors.Is
	}{
		{
			name: "open",
			ctx:  context.Background(),
			err:  nil,
			want: StateOpen,
		},
		{
			name:      "context canceled",
			ctx:       context.Background(),
			err:       context.Canceled,
			want:      StateCanceled,
			wantErr:   true,
			wantErrIs: context.Canceled,
		},
		{
			name:      "context deadline exceeded",
			ctx:       context.Background(),
			err:       context.DeadlineExceeded,
			want:      StateCanceled,
			wantErr:   true,
			wantErrIs: context.DeadlineExceeded,
		},
		{
			name:      "parent context wins over dial error",
			ctx:       canceledCtx,
			err:       testTimeoutError{},
			want:      StateCanceled,
			wantErr:   true,
			wantErrIs: context.Canceled,
		},
		{
			name:    "net timeout",
			ctx:     context.Background(),
			err:     testTimeoutError{},
			want:    StateTimeout,
			wantErr: true,
		},
		{
			name:    "os deadline exceeded",
			ctx:     context.Background(),
			err:     os.ErrDeadlineExceeded,
			want:    StateTimeout,
			wantErr: true,
		},
		{
			name:    "wrapped net timeout",
			ctx:     context.Background(),
			err:     &net.OpError{Op: "dial", Net: "tcp", Err: testTimeoutError{}},
			want:    StateTimeout,
			wantErr: true,
		},
		{
			name:    "generic error",
			ctx:     context.Background(),
			err:     errors.New("some local failure"),
			want:    StateError,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, resultErr := classifyConnectError(tc.ctx, tc.err)
			if state != tc.want {
				t.Fatalf("state = %s, want %s", state, tc.want)
			}
			if !tc.wantErr {
				if resultErr != nil {
					t.Fatalf("Err = %v, want nil", resultErr)
				}
				return
			}
			if resultErr == nil {
				t.Fatal("Err = nil, want the underlying error")
			}
			if tc.wantErrIs != nil && !errors.Is(resultErr, tc.wantErrIs) {
				t.Fatalf("Err = %v, want errors.Is(_, %v)", resultErr, tc.wantErrIs)
			}
		})
	}
}

func TestClassifyConnectErrorErrno(t *testing.T) {
	tests := []struct {
		name  string
		errno syscall.Errno
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

func TestClassifyResolveError(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true}

	state, resultErr := classifyResolveError(context.Background(), dnsErr)
	if state != StateError {
		t.Fatalf("state = %s, want %s", state, StateError)
	}
	var gotDNS *net.DNSError
	if !errors.As(resultErr, &gotDNS) || gotDNS.Name != dnsErr.Name {
		t.Fatalf("Err = %v, want wrapped *net.DNSError", resultErr)
	}

	state, resultErr = classifyResolveError(context.Background(), testTimeoutError{})
	if state != StateTimeout || resultErr == nil {
		t.Fatalf("timeout: state = %s, err = %v", state, resultErr)
	}
}

func TestStateString(t *testing.T) {
	tests := map[State]string{
		StateOpen:        "open",
		StateClosed:      "closed",
		StateTimeout:     "timeout",
		StateUnreachable: "unreachable",
		StateCanceled:    "canceled",
		StateError:       "error",
		State(""):        "unknown",
		State("bogus"):   "unknown",
	}
	for state, want := range tests {
		if got := state.String(); got != want {
			t.Errorf("State(%q).String() = %q, want %q", string(state), got, want)
		}
	}
	if want := fmt.Sprintf("%s", StateOpen); want != "open" {
		t.Errorf("formatted state = %q, want open", want)
	}
}
