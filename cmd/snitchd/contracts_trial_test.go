// contracts_trial_test.go: the persistent-trial spec's daemon-side contracts, one test per
// Require line of ctl.require, asserting the message so each test trips exactly its line.
package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

// completeCtl is a ctl with every writer, probe and delegate set (fakes that touch neither
// the file system nor the maps), as root; the contract tests blank one slot at a time.
func completeCtl() *ctl {
	c := newCtl(&bytes.Buffer{}, &bytes.Buffer{}, probes{
		control: func() (time.Duration, uint32, uint32, bool) { return 0, 0, 0, false },
		kill:    func() bool { return false },
	})
	c.euid = func() int { return 0 }
	c.deps = deps{
		store: func(dir string) trial.Store {
			st := (&memFS{files: map[string]string{}}).store()
			st.Dir = dir
			return st
		},
		dirExists:  func(string) bool { return false },
		readStatus: func(string) (status.Record, error) { return status.Record{}, nil },
		bootID:     func() (string, error) { return tBoot, nil },
		now:        func() time.Time { return tNow },
		confirm:    func(string) bool { return false },
	}
	return c
}

// Every handler requires its writers and probes (ctl.require's first line) and its delegates
// (the second); each slot blank on its own trips the line that names it, for every verb that
// talks to the daemon (check runs without root and uses none of them: ctl_check_test.go).
func TestContractEveryVerbNamesTheMissingSlot(t *testing.T) {
	completeCtl().require() // the fixture itself passes: a blank slot is what trips below
	const writers, delegates = "ctl: incomplete writers or probes", "ctl: incomplete deps"
	blank := []struct {
		slot, want string
		set        func(c *ctl)
	}{
		{"out", writers, func(c *ctl) { c.out = nil }},
		{"errw", writers, func(c *ctl) { c.errw = nil }},
		{"probes.control", writers, func(c *ctl) { c.probes.control = nil }},
		{"probes.kill", writers, func(c *ctl) { c.probes.kill = nil }},
		{"deps.store", delegates, func(c *ctl) { c.deps.store = nil }},
		{"deps.dirExists", delegates, func(c *ctl) { c.deps.dirExists = nil }},
		{"deps.readStatus", delegates, func(c *ctl) { c.deps.readStatus = nil }},
		{"deps.bootID", delegates, func(c *ctl) { c.deps.bootID = nil }},
		{"deps.now", delegates, func(c *ctl) { c.deps.now = nil }},
		{"deps.confirm", delegates, func(c *ctl) { c.deps.confirm = nil }},
	}
	for _, v := range verbs {
		if !v.root {
			continue
		}
		for _, b := range blank {
			c := completeCtl()
			b.set(c)
			got := contracttest.Panics(t, contract.Precondition, func() { dispatch(verbs, c, []string{v.name}) })
			if got.Msg != b.want {
				t.Errorf("%s with no %s: violation %q, want %q", v.name, b.slot, got.Msg, b.want)
			}
		}
	}
}
