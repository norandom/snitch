package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/norandom/snitch/internal/api"
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
	r.load = func(p, overlay string, notice func(string)) (*snapshot, error) {
		r.st.publish(&snapshot{res: &rules.Resolved{File: &rules.File{}}})
		return loadRules(p, overlay, notice)
	}
	contracttest.Panics(t, contract.InvariantKind, func() { r.reload(true) })
}

// Design "Contracts": an API rule edit before the first snapshot is published is a bug in the
// daemon's start order (the API is installed after the first load); apiJobs with the API on
// needs the reloader for the rules-error fact.
func TestContractAPIEditsNeedTheFirstSnapshot(t *testing.T) {
	d := &daemon{}
	req := api.Request{Type: "rule.add", Program: "curl", To: "1.1.1.1", Verdict: "allow"}
	v := contracttest.Panics(t, contract.Precondition, func() { _, _ = d.ruleAdd(req) })
	if v.Msg != "ruleAdd before the first snapshot" {
		t.Fatalf("ruleAdd: %q", v.Msg)
	}
	req.Type = "rule.remove"
	v = contracttest.Panics(t, contract.Precondition, func() { _, _ = d.ruleRemove(req) })
	if v.Msg != "ruleRemove before the first snapshot" {
		t.Fatalf("ruleRemove: %q", v.Msg)
	}
	on := &daemon{cfg: config{api: filepath.Join(t.TempDir(), "no", "such", "api.sock")}, log: func(string) {}}
	if v = contracttest.Panics(t, contract.Precondition, func() { on.apiJobs(nil) }); v.Msg != "apiJobs needs the reloader" {
		t.Fatalf("apiJobs: %q", v.Msg)
	}
}
