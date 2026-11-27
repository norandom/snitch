// hook.go: probes and caches the kernel's BPF LSM hook state at daemon startup and on status
// reads, formatting it into the API's HookStatus fact.
//
// Fail-safe implications: the probe only reads securityfs, kernel build config, and GRUB
// config; an inactive or unknown hook never fails startup, denies a connection, changes the
// daemon mode, or alters the kill switch or trial/kept store.
package main

import (
	"os"
	"sync"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/lsm"
)

// hookTTL is how long a cached probe is kept before re-probing (the active LSM list is fixed
// at boot, while pending can change after a package install or update-grub).
const hookTTL = 30 * time.Second

type hookCache struct {
	mu     sync.Mutex
	read   func(string) ([]byte, error) // nil = os.ReadFile
	clock  func() time.Time             // nil = time.Now
	val    lsm.Hook
	at     time.Time
	probed bool
}

// start probes the kernel hook once and logs its fixed one-line sentence.
func (c *hookCache) start(log func(string)) {
	contract.Require(log != nil, "hookCache.start: nil log")
	log(c.probe().Sentence())
}

func (c *hookCache) probe() lsm.Hook {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshLocked(c.timeLocked())
}

// now returns the cached hook probe, re-probing when empty or older than hookTTL.
func (c *hookCache) now() lsm.Hook {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.timeLocked()
	if !c.probed || c.val.State == "" || t.Sub(c.at) >= hookTTL {
		return c.refreshLocked(t)
	}
	return c.val
}

func (c *hookCache) timeLocked() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

func (c *hookCache) refreshLocked(at time.Time) lsm.Hook {
	read := c.read
	if read == nil {
		read = os.ReadFile
	}
	c.val = lsm.Probe(read)
	c.at = at
	c.probed = true
	return c.val
}

func (d *daemon) hookNow() lsm.Hook { return d.hook.now() }

// hookStatus converts h into the API's wire representation, keeping Pending and Unsupported
// clear unless State is Inactive.
func hookStatus(h lsm.Hook) *api.HookStatus {
	s := &api.HookStatus{
		State:  string(h.State),
		Reason: h.Sentence(),
	}
	if h.State == lsm.Inactive {
		s.Pending = h.Pending
		s.Unsupported = h.Unsupported
	}
	return s
}
