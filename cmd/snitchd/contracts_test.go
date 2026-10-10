package main

import (
	"os"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

func TestContractPublishNeedsABuiltSnapshot(t *testing.T) {
	var st state
	contracttest.Panics(t, contract.Precondition, func() { st.publish(nil) })
	contracttest.Panics(t, contract.Precondition, func() { st.publish(&snapshot{}) })
}

func TestContractReloadDetectsAMovedBase(t *testing.T) {
	// a loader that publishes behind the reloader's back: the base moved, the diff is stale
	self, _ := os.Executable()
	path := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n")
	r, _ := newReloader(t, path, &recorder{})
	r.st.publish(snapWith(self, ""))
	r.load = func(p string, notice func(string)) (*snapshot, error) {
		r.st.publish(&snapshot{res: &rules.Resolved{File: &rules.File{}}})
		return loadRules(p, notice)
	}
	contracttest.Panics(t, contract.InvariantKind, func() { r.reload(true) })
}
