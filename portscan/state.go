package portscan

// State describes the outcome of a TCP connect attempt.
type State string

const (
	// StateOpen means that a TCP connection was established successfully.
	StateOpen State = "open"

	// StateClosed means that the peer explicitly rejected the connection
	// (for example, with a TCP RST).
	StateClosed State = "closed"

	// StateTimeout means that the connection attempt did not finish within
	// the configured connect timeout.
	StateTimeout State = "timeout"

	// StateUnreachable means that the host or the network was reported as
	// unreachable by the operating system.
	StateUnreachable State = "unreachable"

	// StateCanceled means that the scan was canceled through its
	// context.Context.
	StateCanceled State = "canceled"

	// StateError means that the connection failed for another reason, for
	// example because of a local resource problem.
	StateError State = "error"
)

// String returns the textual representation of the state.
func (s State) String() string {
	switch s {
	case StateOpen, StateClosed, StateTimeout, StateUnreachable, StateCanceled, StateError:
		return string(s)
	default:
		return "unknown"
	}
}
