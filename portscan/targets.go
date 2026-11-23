package portscan

import (
	"fmt"
	"net/netip"
	"strings"
)

// target is a validated scan target. Exactly one of addr (a literal IP
// address) and name (a DNS name) is set.
type target struct {
	host string
	name string
	addr netip.Addr
	key  string
}

func (t target) isLiteral() bool { return t.addr.IsValid() }

// parseTargets validates hosts, removes duplicates and preserves the original
// order of first occurrences.
//
// Duplicates are detected by canonical IP address for literals and
// case-insensitively for DNS names. CIDR notation is deliberately not
// supported and is reported as an invalid host.
func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}

	targets := make([]target, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))

	for _, raw := range hosts {
		t, err := parseTarget(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[t.key]; ok {
			continue
		}
		seen[t.key] = struct{}{}
		targets = append(targets, t)
	}

	return targets, nil
}

func parseTarget(raw string) (target, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return target{}, fmt.Errorf("%w: host is empty", ErrInvalidHost)
	}

	literal := host
	if strings.HasPrefix(literal, "[") || strings.HasSuffix(literal, "]") {
		if !strings.HasPrefix(literal, "[") || !strings.HasSuffix(literal, "]") {
			return target{}, fmt.Errorf("%w: %q has unbalanced brackets", ErrInvalidHost, raw)
		}
		literal = literal[1 : len(literal)-1]
		addr, err := netip.ParseAddr(literal)
		if err != nil {
			return target{}, fmt.Errorf("%w: %q is not a valid IP address", ErrInvalidHost, raw)
		}
		return literalTarget(addr), nil
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		return literalTarget(addr), nil
	}

	// A colon can only appear in an IPv6 literal, a slash starts a CIDR
	// prefix, and brackets/percent signs are invalid in DNS names.
	if strings.ContainsAny(host, ":/%[]") {
		return target{}, fmt.Errorf("%w: %q is not a valid IP address or host name", ErrInvalidHost, raw)
	}

	if err := validateDNSName(host); err != nil {
		return target{}, fmt.Errorf("%w: %q: %v", ErrInvalidHost, raw, err)
	}

	return target{
		host: host,
		name: host,
		key:  "dns:" + strings.ToLower(strings.TrimSuffix(host, ".")),
	}, nil
}

func literalTarget(addr netip.Addr) target {
	addr = addr.Unmap()
	return target{
		host: addr.String(),
		addr: addr,
		key:  "ip:" + addr.String(),
	}
}

func validateDNSName(name string) error {
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return fmt.Errorf("empty host name")
	}
	if len(trimmed) > 253 {
		return fmt.Errorf("host name is longer than 253 bytes")
	}

	labels := strings.Split(trimmed, ".")
	allNumeric := true
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("empty DNS label")
		}
		if len(label) > 63 {
			return fmt.Errorf("DNS label %q is longer than 63 bytes", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS label %q starts or ends with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-', c == '_':
			default:
				return fmt.Errorf("DNS label %q contains an unsupported character", label)
			}
		}
		if !isDecimalLabel(label) {
			allNumeric = false
		}
	}

	// Strings such as 999.999.999.999 are syntactically valid DNS names but
	// are almost certainly malformed IP addresses. Reject them instead of
	// turning them into a slow DNS lookup.
	if len(labels) > 1 && allNumeric {
		return fmt.Errorf("looks like a malformed IPv4 address")
	}

	return nil
}

func isDecimalLabel(label string) bool {
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}
