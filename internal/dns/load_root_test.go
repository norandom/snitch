//go:build root

// This load-only test uses an isolated trie and never attaches or changes traffic policy.
package dns

import (
	"testing"

	"github.com/cilium/ebpf"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
)

func TestDNSProgLoads(t *testing.T) {
	snitchSpec, err := snitchbpf.LoadSnitch()
	if err != nil {
		t.Fatal(err)
	}
	trie, err := ebpf.NewMap(snitchSpec.Maps["rules"])
	if err != nil {
		t.Fatal(err)
	}
	defer trie.Close()
	spec, err := snitchbpf.LoadDns()
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"rules": trie},
	})
	if err != nil {
		t.Fatalf("load DNS programs: %+v", err)
	}
	defer collection.Close()
	checkLoadedPrograms(t, collection)
}

func checkLoadedPrograms(t *testing.T, collection *ebpf.Collection) {
	t.Helper()
	for _, name := range []string{"dns_query", "dns_answer"} {
		prog := collection.Programs[name]
		if prog == nil {
			t.Fatalf("missing loaded program %s", name)
		}
		info, err := prog.Info()
		if err != nil {
			t.Fatal(err)
		}
		count, available := info.VerifiedInstructions()
		if !available {
			t.Fatalf("%s: verified instruction count unavailable", name)
		}
		t.Logf("%s: %d verified instructions", name, count)
	}
}
