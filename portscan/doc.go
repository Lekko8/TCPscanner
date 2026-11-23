// Package portscan performs concurrent TCP connect scans and reports the
// state of every requested host/port pair.
//
// The package is intended to be embedded into other applications. It has no
// dependencies outside the standard library and no global mutable state.
//
// A scan consists of three phases:
//
//  1. Input validation. Invalid hosts, ports and options are reported
//     synchronously by Scan or New.
//  2. Name resolution. Literal IP addresses are used as is; DNS names are
//     resolved concurrently into all of their A and AAAA addresses.
//  3. TCP connect probing. A bounded worker pool tries to establish a TCP
//     connection to every (address, port) pair. Established connections are
//     closed immediately; they are never used to exchange application data.
//
// Only ordinary TCP connect scanning is implemented. SYN scanning, UDP
// scanning, raw sockets, OS fingerprinting and firewall evasion are out of
// scope.
//
// # Result delivery
//
// Scan returns a channel that is closed when the scan is finished. Results
// arrive in completion order, not in target or port order. A single DNS name
// may resolve to several addresses; in that case one result is produced for
// every address and port.
//
// The result channel is bounded. If the caller stops reading, workers block,
// which provides natural backpressure and keeps memory usage bounded. The
// caller must either drain the channel or cancel the context. Cancellation
// never leaves the scanner's goroutines blocked: all network operations are
// tied to the context.
//
// # Cancellation
//
// After the context is canceled, no new connection attempts are started.
// Already started attempts are canceled and may be reported with
// StateCanceled. Probes that were never started are not reported. The result
// channel is closed once all in-flight attempts have stopped. Delivery of
// canceled results is best effort: results that cannot be delivered without
// blocking are dropped, because the channel is closed instead of waiting for
// a consumer that may have stopped reading.
package portscan
