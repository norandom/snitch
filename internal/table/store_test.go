package table

import (
	"testing"

	"github.com/norandom/snitch/internal/api"
)

func TestStoreKeyOf(t *testing.T) {
	declared := api.Entry{
		Program: "curl", Path: "/usr/bin/curl",
		Addr: "1.1.1.1", Port: 443, Protocol: "tcp",
	}
	if got, want := KeyOf(declared), (Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}); got != want {
		t.Fatalf("declared KeyOf = %+v, want %+v", got, want)
	}

	unmapped := api.Entry{
		Program: "unknown", Path: "/usr/bin/dig",
		Addr: "2620:fe::fe", Port: 53, Protocol: "udp",
	}
	if got, want := KeyOf(unmapped), (Key{Who: "/usr/bin/dig", Addr: "2620:fe::fe", Proto: "udp", Port: 53}); got != want {
		t.Fatalf("unmapped KeyOf = %+v, want %+v", got, want)
	}

	bucket := api.Entry{Program: "unknown"}
	if got, want := KeyOf(bucket), (Key{Who: "unknown"}); got != want {
		t.Fatalf("bucket KeyOf = %+v, want %+v", got, want)
	}
}

func TestStoreReplace(t *testing.T) {
	e1 := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 100}
	e2 := api.Entry{Program: "unknown", Path: "/usr/bin/dig", Addr: "9.9.9.9", Port: 53, Protocol: "udp", BytesSent: 200}
	bucket := api.Entry{Program: "unknown", BytesSent: 50}

	s1 := (Store{}).Replace([]api.Entry{e1, e2, bucket})
	if s1.Len() != 3 {
		t.Fatalf("s1.Len() = %d, want 3", s1.Len())
	}
	s2 := s1.Replace([]api.Entry{e2})
	if s2.Len() != 1 {
		t.Fatalf("s2.Len() = %d, want 1", s2.Len())
	}
	if _, ok := s2.Get(KeyOf(e1)); ok {
		t.Fatalf("s2 still contains e1 after Replace")
	}
	if got, ok := s2.Get(KeyOf(e2)); !ok || got.BytesSent != 200 {
		t.Fatalf("s2 e2 = %+v, ok=%v", got, ok)
	}
	if empty := s2.Replace(nil); empty.Len() != 0 {
		t.Fatalf("Replace(nil) Len() = %d, want 0", empty.Len())
	}
}

func TestStoreUpsertIsImmutable(t *testing.T) {
	e1 := api.Entry{Program: "curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 100, AllowCount: 1}
	e2 := api.Entry{Program: "unknown", Path: "/usr/bin/dig", Addr: "9.9.9.9", Port: 53, Protocol: "udp", BytesSent: 200}
	s1 := (Store{}).Replace([]api.Entry{e1, e2})

	e1Updated := e1
	e1Updated.BytesSent, e1Updated.AllowCount = 500, 3
	e3 := api.Entry{Program: "curl", Addr: "8.8.8.8", Port: 443, Protocol: "tcp", BytesSent: 300, DenyCount: 1}

	s2 := s1.Upsert([]api.Entry{e1Updated, e3})
	if s2.Len() != 3 {
		t.Fatalf("s2.Len() = %d, want 3", s2.Len())
	}
	if got, ok := s1.Get(KeyOf(e1)); !ok || got.BytesSent != 100 {
		t.Fatalf("s1 mutated: got=%+v ok=%v", got, ok)
	}
	if _, ok := s1.Get(KeyOf(e3)); ok {
		t.Fatalf("s1 unexpectedly contains e3")
	}
	if got, ok := s2.Get(KeyOf(e1)); !ok || got.BytesSent != 500 || got.AllowCount != 3 {
		t.Fatalf("s2 e1 = %+v, ok=%v", got, ok)
	}
	if same := s2.Upsert(nil); same.Len() != 3 {
		t.Fatalf("Upsert(nil) Len() = %d, want 3", same.Len())
	}
}
