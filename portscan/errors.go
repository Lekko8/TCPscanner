package portscan

import "errors"

var (
	// ErrInvalidOption is returned by New when an option value is invalid.
	ErrInvalidOption = errors.New("portscan: invalid option")

	// ErrNilScanner is returned when Scan is called on a nil *Scanner.
	ErrNilScanner = errors.New("portscan: nil scanner")

	// ErrNilContext is returned when Scan receives a nil context.
	ErrNilContext = errors.New("portscan: nil context")

	// ErrNoHosts is returned when the host list is empty.
	ErrNoHosts = errors.New("portscan: no hosts to scan")

	// ErrInvalidHost is returned for an empty, malformed or unsupported host.
	ErrInvalidHost = errors.New("portscan: invalid host")

	// ErrNoPorts is returned when the port specification is empty.
	ErrNoPorts = errors.New("portscan: no ports to scan")

	// ErrInvalidPort is returned for a port outside the range 1..65535.
	ErrInvalidPort = errors.New("portscan: invalid port")

	// ErrInvalidPortRange is returned for a range whose start is greater
	// than its end.
	ErrInvalidPortRange = errors.New("portscan: invalid port range")

	// ErrNoAddresses is placed in Result.Err when a DNS name resolves to an
	// empty address list.
	ErrNoAddresses = errors.New("portscan: host resolved to no addresses")
)
