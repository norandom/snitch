package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
)

func TestRunJobsViolationInsideAJobExits70WithAStack(t *testing.T) {
	var logs []string
	code := runJobs(func(m string) { logs = append(logs, m) },
		func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		func(context.Context) error { contract.Invariant(false, "ids drifted"); return nil },
	)
	if code != exitViolation {
		t.Fatalf("want exit %d, got %d", exitViolation, code)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "contract invariant: ids drifted") || !strings.Contains(logs[0], "goroutine") {
		t.Fatalf("want the violation and a stack, got %q", logs)
	}
}

func TestRunJobsOutcomes(t *testing.T) {
	quiet := func(string) {}
	if code := runJobs(quiet, jobs.After(1)); code != 0 { // 1 ns deadline
		t.Fatalf("deadline: want 0, got %d", code)
	}
	if code := runJobs(quiet, func(context.Context) error { return errStop }); code != 0 {
		t.Fatalf("stop: want 0, got %d", code)
	}
	if code := runJobs(quiet, func(context.Context) error { return errors.New("heartbeat: EIO") }); code != 1 {
		t.Fatalf("error: want 1, got %d", code)
	}
}

func TestGuardLetsOtherPanicsThrough(t *testing.T) {
	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("want the original panic, got %v", r)
		}
	}()
	guard(func(context.Context) error { panic("boom") })(context.Background())
}
