package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/rules"
)

const learnWritePeriod = 60 * time.Second // Req 9.7: a crash loses at most a minute

// learner is learning mode: the sink the pump feeds and the job that writes the file. The
// writer is a delegate so tests do not touch the disk. Observations arrive from the pump
// goroutine, writes from the job: one mutex.
type learner struct {
	mu      sync.Mutex
	path    string
	set     *rules.Learned
	pending *rules.File // projected but not yet written (a failed write keeps it for the retry)
	write   func(path string, f *rules.File) error
	log     func(string)
}

// newLearner seeds from an existing learned file. A missing file is fine; an invalid one is
// an error (the operator edited it) and the daemon refuses to start.
func newLearner(path string, write func(string, *rules.File) error, log func(string)) (*learner, error) {
	seed, err := rules.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		seed = nil
	case err != nil:
		return nil, fmt.Errorf("learned file: %w", err)
	default:
		log(fmt.Sprintf("learning continues from %s (%d rules)", path, len(seed.Rules)))
	}
	return &learner{path: path, set: rules.NewLearned(seed), write: write, log: log}, nil
}

// observe is the pump's sink.
func (l *learner) observe(o rules.Observation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.set.Observe(o)
}

// observations is the API's read of the learned set (Req 4.4): under the mutex, through the
// projection that leaves the dirty flag alone, so the next flush still writes.
func (l *learner) observations() []rules.Observed {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set.Observations()
}

// flush writes the file if anything changed; a failure is logged (the run goes on, the next
// flush retries) and reported so the final flush can be checked.
func (l *learner) flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.set.Dirty() {
		l.pending = l.set.File() // File() clears the dirty flag: hold the projection until written
	}
	if l.pending == nil {
		return nil
	}
	if err := l.write(l.path, l.pending); err != nil {
		l.log(fmt.Sprintf("learned file not written: %v", err))
		return err
	}
	l.pending = nil
	return nil
}

// job flushes every minute and once more when the run ends. Errors never end the run (jobs.Run
// would discard them anyway: the first job to return wins), so they are logged in flush.
func (l *learner) job() jobs.Job {
	periodic := jobs.Every(learnWritePeriod, func(context.Context) error { l.flush(); return nil })
	return func(ctx context.Context) error {
		err := periodic(ctx)
		l.flush()
		return err
	}
}
