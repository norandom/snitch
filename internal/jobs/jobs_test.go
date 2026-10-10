package jobs_test

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/jobs"
)

var errBoom = errors.New("boom")

func waitCtx(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

func TestFirstErrorCancelsAndAwaitsTheOthers(t *testing.T) {
	var finished atomic.Bool
	other := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond) // Run must wait for this, not just cancel
		finished.Store(true)
		return ctx.Err()
	}
	failing := func(context.Context) error { return errBoom }
	err := jobs.Run(context.Background(), other, failing)
	if !errors.Is(err, errBoom) {
		t.Fatalf("want the first error, got %v", err)
	}
	if !finished.Load() {
		t.Fatal("Run returned before the other job finished")
	}
}

func TestDeadlineEndsTheRunWithNil(t *testing.T) {
	start := time.Now()
	err := jobs.Run(context.Background(), waitCtx, jobs.After(20*time.Millisecond))
	if err != nil || time.Since(start) < 20*time.Millisecond {
		t.Fatalf("want nil after the deadline, got %v after %v", err, time.Since(start))
	}
}

func TestZeroDeadlineNeverFires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := jobs.Run(ctx, jobs.After(0))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the context to end the run, got %v", err)
	}
}

func TestEveryTicksThenStopsWithContext(t *testing.T) {
	ticks := 0
	ctx, cancel := context.WithCancel(context.Background())
	tick := func(context.Context) error {
		ticks++
		if ticks == 3 {
			cancel()
		}
		return nil
	}
	err := jobs.Run(ctx, jobs.Every(time.Millisecond, tick))
	if !errors.Is(err, context.Canceled) || ticks < 3 {
		t.Fatalf("want 3 ticks then Canceled, got %d ticks, %v", ticks, err)
	}
}

func TestEveryTickErrorEndsTheRun(t *testing.T) {
	err := jobs.Run(context.Background(), jobs.Every(time.Millisecond, func(context.Context) error { return errBoom }))
	if !errors.Is(err, errBoom) {
		t.Fatalf("want the tick error, got %v", err)
	}
}

func TestSignalIsDelivered(t *testing.T) {
	got := make(chan os.Signal, 1)
	fn := func(s os.Signal) error { got <- s; return errBoom }
	ready := make(chan struct{})
	kick := func(ctx context.Context) error {
		close(ready)
		return waitCtx(ctx)
	}
	go func() {
		<-ready
		time.Sleep(10 * time.Millisecond) // let OnSignal register before the signal is sent
		_ = syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	}()
	signal.Ignore(syscall.SIGUSR1) // an early delivery must not kill the test binary
	defer signal.Reset(syscall.SIGUSR1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := jobs.Run(ctx, jobs.OnSignal(fn, syscall.SIGUSR1), kick)
	if !errors.Is(err, errBoom) || <-got != syscall.SIGUSR1 {
		t.Fatalf("signal not delivered: %v", err)
	}
}

func TestContractsOnArguments(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { _ = jobs.Run(context.Background()) })
	contracttest.Panics(t, contract.Precondition, func() { jobs.Every(0, nil) })
	contracttest.Panics(t, contract.Precondition, func() { jobs.OnSignal(nil) })
	contracttest.Panics(t, contract.Precondition, func() { jobs.After(-time.Second) })
}
