package portscan

import (
	"errors"
	"testing"
)

func TestParseTargetsRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		want  error
	}{
		{name: "no hosts", hosts: nil, want: ErrNoHosts},
		{name: "empty slice", hosts: []string{}, want: ErrNoHosts},
		{name: "empty host", hosts: []string{""}, want: ErrInvalidHost},
		{name: "whitespace host", hosts: []string{"   "}, want: ErrInvalidHost},
		{name: "malformed IPv4", hosts: []string{"999.999.999.999"}, want: ErrInvalidHost},
		{name: "malformed IPv6", hosts: []string{"2001:db8::zz"}, want: ErrInvalidHost},
		{name: "CIDR is unsupported", hosts: []string{"10.0.0.0/8"}, want: ErrInvalidHost},
		{name: "space in DNS name", hosts: []string{"bad host"}, want: ErrInvalidHost},
		{name: "empty DNS label", hosts: []string{"example..com"}, want: ErrInvalidHost},
		{name: "leading hyphen", hosts: []string{"-bad.example"}, want: ErrInvalidHost},
		{name: "trailing hyphen", hosts: []string{"bad-.example"}, want: ErrInvalidHost},
		{name: "unsupported Unicode", hosts: []string{"example.рф"}, want: ErrInvalidHost},
		{name: "unbalanced brackets", hosts: []string{"[::1"}, want: ErrInvalidHost},
		{name: "bad bracketed address", hosts: []string{"[example.com]"}, want: ErrInvalidHost},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTargets(tc.hosts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("parseTargets(%q) error = %v, want errors.Is(_, %v)", tc.hosts, err, tc.want)
			}
		})
	}
}

func TestParseTargetsNormalizesAndDeduplicates(t *testing.T) {
	hosts := []string{
		" 127.0.0.1 ",
		"127.0.0.1",
		"::1",
		"0:0:0:0:0:0:0:1",
		"[::1]",
		"::ffff:127.0.0.1",
		"Example.COM",
		"example.com",
		"example.com.",
	}

	targets, err := parseTargets(hosts)
	if err != nil {
		t.Fatalf("parseTargets() error = %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3: %+v", len(targets), targets)
	}

	if targets[0].host != "127.0.0.1" || !targets[0].isLiteral() {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[1].host != "::1" || !targets[1].isLiteral() {
		t.Fatalf("unexpected second target: %+v", targets[1])
	}
	if targets[2].host != "Example.COM" || targets[2].isLiteral() {
		t.Fatalf("unexpected third target: %+v", targets[2])
	}
}

func TestParseTargetsAcceptsDNSNames(t *testing.T) {
	for _, host := range []string{"localhost", "example.com", "example.com.", "_service._tcp.example.com", "xn--e1afmkfd.xn--p1ai"} {
		if _, err := parseTargets([]string{host}); err != nil {
			t.Errorf("parseTargets(%q) error = %v, want nil", host, err)
		}
	}
}

func TestParseTargetsAcceptsIPv6Zone(t *testing.T) {
	targets, err := parseTargets([]string{"fe80::1%loopback"})
	if err != nil {
		t.Fatalf("parseTargets() error = %v", err)
	}
	if len(targets) != 1 || !targets[0].isLiteral() {
		t.Fatalf("unexpected targets: %+v", targets)
	}
	if targets[0].addr.Zone() != "loopback" {
		t.Fatalf("zone = %q, want loopback", targets[0].addr.Zone())
	}
	if targets[0].host != "fe80::1%loopback" {
		t.Fatalf("host = %q", targets[0].host)
	}
}
