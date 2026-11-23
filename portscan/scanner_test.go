package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	mu    sync.Mutex
	calls []string
	fn    func(ctx context.Context, host string) ([]netip.Addr, error)
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.calls = append(f.calls, host)
	f.mu.Unlock()

	if f.fn != nil {
		return f.fn(ctx, host)
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type recordingConn struct {
	closed *atomic.Int32
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *recordingConn) Close() error                     { c.closed.Add(1); return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

func mustScanner(t *testing.T, opts ...Option) *Scanner {
	t.Helper()
	s, err := New(opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

func scanAndCollect(t *testing.T, ctx context.Context, s *Scanner, hosts []string, ports Ports) []Result {
	t.Helper()
	results, err := s.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	var collected []Result
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func TestZeroValueScannerUsesDefaults(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	var s Scanner
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, &s, []string{"127.0.0.1"}, List(port))
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].State != StateOpen {
		t.Fatalf("state = %s, want open; err = %v", results[0].State, results[0].Err)
	}
}

func TestScanOpenAndClosedAgainstLoopback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	openPort := listener.Addr().(*net.TCPAddr).Port

	closedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	if err := closedListener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	s := mustScanner(t, WithConcurrency(4), WithConnectTimeout(2*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"127.0.0.1"}, List(openPort, closedPort))
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	byPort := make(map[uint16]Result, len(results))
	for _, result := range results {
		byPort[result.Port] = result

		if result.Host != "127.0.0.1" {
			t.Errorf("Host = %q, want 127.0.0.1", result.Host)
		}
		if result.IP.String() != "127.0.0.1" {
			t.Errorf("IP = %v, want 127.0.0.1", result.IP)
		}
		if result.Duration < 0 {
			t.Errorf("negative duration: %s", result.Duration)
		}
	}

	if got := byPort[uint16(openPort)]; got.State != StateOpen || got.Err != nil {
		t.Errorf("open port: state = %s, err = %v", got.State, got.Err)
	}
	if got := byPort[uint16(closedPort)]; got.State != StateClosed || got.Err != nil {
		t.Errorf("closed port: state = %s, err = %v", got.State, got.Err)
	}

	// The scanner must close established connections. The accepted socket
	// should observe EOF, not an open connection.
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Now().Add(2 * time.Second))
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read from accepted connection = %v, want EOF", err)
	}
}

func TestScanRespectsConcurrencyLimit(t *testing.T) {
	const limit = 4

	var active, maxActive atomic.Int32
	var closedCount atomic.Int32

	s := mustScanner(t, WithConcurrency(limit), WithConnectTimeout(time.Second))
	s.resolver = &fakeResolver{}
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		current := active.Add(1)
		for {
			observed := maxActive.Load()
			if current <= observed || maxActive.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		return &recordingConn{closed: &closedCount}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"example.test"}, List(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20))
	if len(results) != 20 {
		t.Fatalf("got %d results, want 20", len(results))
	}
	for _, result := range results {
		if result.State != StateOpen {
			t.Fatalf("state = %s, want open; err = %v", result.State, result.Err)
		}
	}
	if got := maxActive.Load(); got > limit {
		t.Fatalf("max concurrent connections = %d, want <= %d", got, limit)
	} else if got < 2 {
		t.Fatalf("max concurrent connections = %d, expected the pool to overlap", got)
	}
	if got := closedCount.Load(); got != 20 {
		t.Fatalf("closed connections = %d, want 20", got)
	}
}

func TestScanCancellationStopsInFlightProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 8)

	s := mustScanner(t, WithConcurrency(4), WithConnectTimeout(time.Minute))
	s.resolver = &fakeResolver{}
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	results, err := s.Scan(ctx, []string{"127.0.0.1"}, List(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("no probe was started")
	}
	cancel()

	done := make(chan []Result, 1)
	go func() {
		var collected []Result
		for result := range results {
			collected = append(collected, result)
		}
		done <- collected
	}()

	select {
	case collected := <-done:
		for _, result := range collected {
			if result.State != StateCanceled {
				t.Errorf("state = %s, want canceled", result.State)
			}
			if !errors.Is(result.Err, context.Canceled) {
				t.Errorf("Err = %v, want context.Canceled", result.Err)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("result channel was not closed after cancellation")
	}
}

func TestScanCancellationClosesChannelWithSlowConsumer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var closedCount atomic.Int32

	s := mustScanner(t, WithConcurrency(4), WithConnectTimeout(time.Second))
	s.resolver = &fakeResolver{}
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &recordingConn{closed: &closedCount}, nil
	}

	results, err := s.Scan(ctx, []string{"127.0.0.1"}, Range(1, 200))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Do not read for a while. The bounded channel fills up and workers
	// block on delivery; cancellation must unblock everything.
	time.Sleep(30 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("scanner goroutines did not stop after cancellation")
	}
}

func TestScanResolvesAllAddresses(t *testing.T) {
	resolver := &fakeResolver{fn: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("::1"),
			netip.MustParseAddr("127.0.0.1"), // duplicate
		}, nil
	}}

	var mu sync.Mutex
	var dialed []string

	s := mustScanner(t, WithConcurrency(2), WithConnectTimeout(time.Second))
	s.resolver = resolver
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, address)
		mu.Unlock()
		return &recordingConn{closed: new(atomic.Int32)}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"example.test"}, List(80, 443))
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4 (2 addresses x 2 ports)", len(results))
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.callCount())
	}

	byIP := make(map[string]map[uint16]bool)
	for _, result := range results {
		if result.Host != "example.test" {
			t.Errorf("Host = %q", result.Host)
		}
		if result.State != StateOpen {
			t.Errorf("state = %s, want open", result.State)
		}
		if byIP[result.IP.String()] == nil {
			byIP[result.IP.String()] = make(map[uint16]bool)
		}
		byIP[result.IP.String()][result.Port] = true
	}
	if !byIP["127.0.0.1"][80] || !byIP["127.0.0.1"][443] {
		t.Errorf("missing IPv4 results: %+v", byIP)
	}
	if !byIP["::1"][80] || !byIP["::1"][443] {
		t.Errorf("missing IPv6 results: %+v", byIP)
	}

	if len(dialed) != 4 {
		t.Fatalf("dialed %d addresses, want 4: %v", len(dialed), dialed)
	}
	for _, address := range dialed {
		if address != "127.0.0.1:80" && address != "127.0.0.1:443" &&
			address != "[::1]:80" && address != "[::1]:443" {
			t.Errorf("unexpected dial address %q", address)
		}
	}
}

func TestScanDNSFailureIsReportedPerPort(t *testing.T) {
	resolver := &fakeResolver{fn: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}}

	s := mustScanner(t, WithConcurrency(2), WithConnectTimeout(time.Second))
	s.resolver = resolver

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"missing.example"}, List(80, 443))
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	for _, result := range results {
		if result.State != StateError {
			t.Errorf("state = %s, want error", result.State)
		}
		if result.IP != nil {
			t.Errorf("IP = %v, want nil", result.IP)
		}
		if result.Duration != 0 {
			t.Errorf("Duration = %s, want 0", result.Duration)
		}
		var dnsErr *net.DNSError
		if !errors.As(result.Err, &dnsErr) {
			t.Errorf("Err = %v, want *net.DNSError", result.Err)
		}
	}
}

func TestScanEmptyAddressList(t *testing.T) {
	resolver := &fakeResolver{fn: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, nil
	}}

	s := mustScanner(t, WithConcurrency(2))
	s.resolver = resolver

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"empty.example"}, List(80))
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].State != StateError || !errors.Is(results[0].Err, ErrNoAddresses) {
		t.Fatalf("result = %+v, want StateError with ErrNoAddresses", results[0])
	}
}

func TestScanDeduplicatesHosts(t *testing.T) {
	resolver := &fakeResolver{}
	s := mustScanner(t, WithConcurrency(2))
	s.resolver = resolver
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &recordingConn{closed: new(atomic.Int32)}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"EXAMPLE.test", "example.test"}, List(80, 443))
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.callCount())
	}
}

func TestScanCancelsDuringResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})

	resolver := &fakeResolver{fn: func(ctx context.Context, host string) ([]netip.Addr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}

	s := mustScanner(t, WithConcurrency(2))
	s.resolver = resolver

	results, err := s.Scan(ctx, []string{"slow.example"}, List(80))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("resolver was not called")
	}
	cancel()

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("result channel was not closed after cancellation during resolution")
	}
}

func TestScanIPv6Literal(t *testing.T) {
	var dialed atomic.Value
	s := mustScanner(t, WithConcurrency(1))
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Store(address)
		return &recordingConn{closed: new(atomic.Int32)}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := scanAndCollect(t, ctx, s, []string{"[::1]"}, List(80))
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	result := results[0]
	if result.Host != "::1" {
		t.Errorf("Host = %q, want ::1", result.Host)
	}
	if result.IP.String() != "::1" {
		t.Errorf("IP = %v, want ::1", result.IP)
	}
	if got := dialed.Load(); got != "[::1]:80" {
		t.Errorf("dialed %q, want [::1]:80", got)
	}
}

func TestScannerReuseConcurrently(t *testing.T) {
	s := mustScanner(t, WithConcurrency(4))
	s.resolver = &fakeResolver{}
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		time.Sleep(time.Millisecond)
		return &recordingConn{closed: new(atomic.Int32)}, nil
	}

	const scans = 4
	const portsPerScan = 10

	var wg sync.WaitGroup
	errs := make(chan error, scans)
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			results, err := s.Scan(ctx, []string{"example.test"}, Range(1, portsPerScan))
			if err != nil {
				errs <- err
				return
			}
			count := 0
			for range results {
				count++
			}
			if count != portsPerScan {
				errs <- fmt.Errorf("got %d results, want %d", count, portsPerScan)
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestScanInputValidation(t *testing.T) {
	s := mustScanner(t, WithConcurrency(1))
	ctx := context.Background()

	tests := []struct {
		name  string
		ctx   context.Context
		hosts []string
		ports Ports
		want  error
	}{
		{name: "no hosts", ctx: ctx, hosts: nil, ports: List(80), want: ErrNoHosts},
		{name: "invalid host", ctx: ctx, hosts: []string{"bad host"}, ports: List(80), want: ErrInvalidHost},
		{name: "no ports", ctx: ctx, hosts: []string{"127.0.0.1"}, ports: Ports{}, want: ErrNoPorts},
		{name: "port zero", ctx: ctx, hosts: []string{"127.0.0.1"}, ports: List(0), want: ErrInvalidPort},
		{name: "port too large", ctx: ctx, hosts: []string{"127.0.0.1"}, ports: List(65536), want: ErrInvalidPort},
		{name: "reversed range", ctx: ctx, hosts: []string{"127.0.0.1"}, ports: Range(1000, 1), want: ErrInvalidPortRange},
		{name: "nil context", ctx: nil, hosts: []string{"127.0.0.1"}, ports: List(80), want: ErrNilContext},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, err := s.Scan(tc.ctx, tc.hosts, tc.ports)
			if results != nil {
				t.Error("result channel is not nil on validation error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want errors.Is(_, %v)", err, tc.want)
			}
		})
	}
}

func TestScanAlreadyCanceledContext(t *testing.T) {
	s := mustScanner(t, WithConcurrency(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := s.Scan(ctx, []string{"127.0.0.1"}, List(80))
	if results != nil {
		t.Error("result channel is not nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestNilScanner(t *testing.T) {
	var s *Scanner
	results, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(80))
	if results != nil {
		t.Error("result channel is not nil")
	}
	if !errors.Is(err, ErrNilScanner) {
		t.Fatalf("error = %v, want ErrNilScanner", err)
	}
}

func TestNewOptions(t *testing.T) {
	s := mustScanner(t)
	if s.concurrency != defaultConcurrency {
		t.Errorf("default concurrency = %d, want %d", s.concurrency, defaultConcurrency)
	}
	if s.connectTimeout != defaultConnectTimeout {
		t.Errorf("default timeout = %s, want %s", s.connectTimeout, defaultConnectTimeout)
	}
	if s.resolver == nil || s.dial == nil {
		t.Error("default resolver or dialer is nil")
	}

	s = mustScanner(t, WithConcurrency(7), WithConnectTimeout(250*time.Millisecond))
	if s.concurrency != 7 {
		t.Errorf("concurrency = %d, want 7", s.concurrency)
	}
	if s.connectTimeout != 250*time.Millisecond {
		t.Errorf("timeout = %s, want 250ms", s.connectTimeout)
	}

	tests := []struct {
		name string
		opts []Option
	}{
		{name: "zero concurrency", opts: []Option{WithConcurrency(0)}},
		{name: "negative concurrency", opts: []Option{WithConcurrency(-1)}},
		{name: "zero timeout", opts: []Option{WithConnectTimeout(0)}},
		{name: "negative timeout", opts: []Option{WithConnectTimeout(-time.Second)}},
		{name: "nil option", opts: []Option{WithConcurrency(1), nil}},
		{name: "typed nil option", opts: []Option{Option(nil)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts...); !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("New() error = %v, want ErrInvalidOption", err)
			}
		})
	}
}
