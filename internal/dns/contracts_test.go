package dns

import "testing"

func TestDecodeContracts(t *testing.T) {
	got, err := DecodeContracts([]uint64{3, 5})
	if err != nil || got != (Contracts{NameShape: 3, DotRange: 5}) {
		t.Fatalf("%+v %v", got, err)
	}
	for _, short := range [][]uint64{nil, {1}} {
		if c, err := DecodeContracts(short); err == nil || c != (Contracts{}) {
			t.Errorf("%d values: %+v %v, want an error", len(short), c, err)
		}
	}
}
