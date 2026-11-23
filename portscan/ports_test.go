package portscan

import (
	"errors"
	"reflect"
	"testing"
)

func TestPortsExpand(t *testing.T) {
	tests := []struct {
		name  string
		ports Ports
		want  []uint16
	}{
		{
			name:  "single port",
			ports: List(80),
			want:  []uint16{80},
		},
		{
			name:  "list is sorted and deduplicated",
			ports: List(443, 80, 443, 22, 80),
			want:  []uint16{22, 80, 443},
		},
		{
			name:  "range",
			ports: Range(20, 23),
			want:  []uint16{20, 21, 22, 23},
		},
		{
			name:  "union of ranges and ports",
			ports: Union(Range(10, 12), List(1, 10), Range(5, 6)),
			want:  []uint16{1, 5, 6, 10, 11, 12},
		},
		{
			name:  "maximum port",
			ports: Range(65535, 65535),
			want:  []uint16{65535},
		},
		{
			name:  "nested union",
			ports: Union(Union(List(3), List(1)), Union(List(2), List(3))),
			want:  []uint16{1, 2, 3},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.ports.expand()
			if err != nil {
				t.Fatalf("expand() error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expand() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPortsExpandErrors(t *testing.T) {
	tests := []struct {
		name  string
		ports Ports
		want  error
	}{
		{name: "zero value", ports: Ports{}, want: ErrNoPorts},
		{name: "empty list", ports: List(), want: ErrNoPorts},
		{name: "empty union", ports: Union(), want: ErrNoPorts},
		{name: "port zero", ports: List(0), want: ErrInvalidPort},
		{name: "negative port", ports: List(-1), want: ErrInvalidPort},
		{name: "port too large", ports: List(65536), want: ErrInvalidPort},
		{name: "range starts at zero", ports: Range(0, 10), want: ErrInvalidPort},
		{name: "range ends too large", ports: Range(10, 65536), want: ErrInvalidPort},
		{name: "reversed range", ports: Range(1000, 1), want: ErrInvalidPortRange},
		{name: "reversed range in union", ports: Union(Range(80, 80), Range(9, 8)), want: ErrInvalidPortRange},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ports.expand()
			if !errors.Is(err, tc.want) {
				t.Fatalf("expand() error = %v, want errors.Is(_, %v)", err, tc.want)
			}
		})
	}
}

func TestPortsExpandDoesNotMutateSource(t *testing.T) {
	first := List(80)
	second := Union(first, List(443))

	gotFirst, err := first.expand()
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := second.expand()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gotFirst, []uint16{80}) {
		t.Fatalf("first set changed: %v", gotFirst)
	}
	if !reflect.DeepEqual(gotSecond, []uint16{80, 443}) {
		t.Fatalf("union = %v, want [80 443]", gotSecond)
	}
}
