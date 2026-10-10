// Package jobs runs a daemon as a list of delegates under one context.
//
// A Job is func(ctx) error. Run starts every job and ends when the first one returns: it
// cancels the context the others see, waits for them, and returns that first result. A nil
// return (a deadline) ends the run as cleanly as an error does.
package jobs

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Job is one long-running activity. It returns when ctx ends or when it decides the run is over.
type Job func(ctx context.Context) error

// Run starts all jobs and returns the first job's result; the others are cancelled and awaited.
func Run(ctx context.Context, js ...Job) error {
	contract.Require(len(js) > 0, "jobs.Run needs at least one job")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	first := make(chan error, len(js))
	var wg sync.WaitGroup
	for _, j := range js {
		wg.Go(func() { first <- j(ctx) })
	}
	err := <-first
	cancel()
	wg.Wait()
	return err
}

// Every calls tick on each period until ctx ends; a tick error ends the job with that error.
func Every(d time.Duration, tick func(context.Context) error) Job {
	contract.Require(d > 0, "jobs.Every needs a positive period")
	return func(ctx context.Context) error {
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				if err := tick(ctx); err != nil {
					return err
				}
			}
		}
	}
}

// OnSignal calls fn for each delivery of sigs until ctx ends or fn returns an error.
func OnSignal(fn func(os.Signal) error, sigs ...os.Signal) Job {
	contract.Require(len(sigs) > 0, "jobs.OnSignal needs at least one signal")
	return func(ctx context.Context) error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, sigs...)
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case s := <-ch:
				if err := fn(s); err != nil {
					return err
				}
			}
		}
	}
}

// After ends the run with nil once d has elapsed; d == 0 means never (the job waits for ctx).
func After(d time.Duration) Job {
	contract.Require(d >= 0, "jobs.After needs a non-negative duration")
	return func(ctx context.Context) error {
		if d == 0 {
			<-ctx.Done()
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}
}
