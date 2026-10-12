// Resolver tests keep map keys consistent with the daemon's address convention.
package dns

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestResolvers(t *testing.T) {
	text := "# nameserver 9.9.9.9\n ; nameserver 8.8.8.8\nsearch example.com\n nameserver 1.1.1.1 # comment\nnameserver fe80::1%eth0;comment\nnameserver 1.1.1.1\nnameserver ::ffff:1.1.1.1\nnameserver bad\nnameserver\n"
	want := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("fe80::1")}
	if got := Resolvers(strings.NewReader(text)); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestResolversCap(t *testing.T) {
	var input strings.Builder
	for i := 1; i <= 17; i++ {
		fmt.Fprintf(&input, "nameserver 192.0.2.%d\n", i)
	}
	got := Resolvers(strings.NewReader(input.String()))
	if len(got) != resolversMax || got[15].String() != "192.0.2.16" {
		t.Fatal(got)
	}
}

func TestResolverKey(t *testing.T) {
	for _, text := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		a := netip.MustParseAddr(text)
		var want [16]byte
		if a.Unmap().Is4() {
			copy(want[:], []byte{192, 0, 2, 1})
		} else {
			want = a.As16()
		}
		if got := ResolverKey(a); got != want {
			t.Errorf("%s: %v != %v", text, got, want)
		}
	}
}
