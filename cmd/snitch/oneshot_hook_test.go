package main

import (
	"os"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client/clienttest"
)

func TestStatusHookInactivePendingAndUnsupported(t *testing.T) {
	asRootPeer(t)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})

	for _, cmd := range []string{"hook inactive", "hook pending"} {
		t.Run(cmd, func(t *testing.T) {
			if err := s.Do(cmd); err != nil {
				t.Fatal(err)
			}
			wantReason := s.Facts().Hook.Reason
			line := mustRunStatus(t, "status", "-api", s.Path())
			if line.Class != "down" || line.Text != "\U000F0499" {
				t.Fatalf("%s: got %#v, want class=down shield allow", cmd, line)
			}
			tipLines := strings.Split(line.Tooltip, "\n")
			if tipLines[0] != wantReason {
				t.Fatalf("%s: first tooltip line = %q, want %q", cmd, tipLines[0], wantReason)
			}
		})
	}

	t.Run("unsupported", func(t *testing.T) {
		reason := "kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked"
		s.SetHook(&api.HookStatus{State: api.HookInactive, Unsupported: true, Reason: reason})
		line := mustRunStatus(t, "status", "-api", s.Path())
		if line.Class != "down" || line.Text != "\U000F0499" {
			t.Fatalf("unsupported: got %#v, want class=down shield allow", line)
		}
		tipLines := strings.Split(line.Tooltip, "\n")
		if tipLines[0] != reason {
			t.Fatalf("unsupported: first tooltip line = %q, want %q", tipLines[0], reason)
		}
	})
}

func TestStatusHookSanitisesHostileReason(t *testing.T) {
	asRootPeer(t)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	evil := "\x1b[31mred\x1b[0m\nfake\tline\r\x7f\u009b\u202ebidi\u200b\ufeff"
	s.SetHook(&api.HookStatus{State: api.HookInactive, Reason: evil})

	line := mustRunStatus(t, "status", "-api", s.Path())
	if line.Class != "down" {
		t.Fatalf("Class = %q, want %q", line.Class, "down")
	}
	tipLines := strings.Split(line.Tooltip, "\n")
	if len(tipLines) != 3 {
		t.Fatalf("expected 3 tooltip lines, got %d: %#v", len(tipLines), tipLines)
	}
	if tipLines[0] != string(clean.Text(evil)) {
		t.Fatalf("first tooltip line = %q, want %q", tipLines[0], string(clean.Text(evil)))
	}
}

func TestStatusHookInactiveOverridesKeptEnforce(t *testing.T) {
	asRootPeer(t)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	if err := s.Do("keep"); err != nil {
		t.Fatal(err)
	}
	if err := s.Do("hook inactive"); err != nil {
		t.Fatal(err)
	}
	wantReason := s.Facts().Hook.Reason
	line := mustRunStatus(t, "status", "-api", s.Path())
	if line.Class != "down" || line.Text != "\U000F0499" {
		t.Fatalf("kept+inactive: got %#v, want class=down shield allow", line)
	}
	tipLines := strings.Split(line.Tooltip, "\n")
	if len(tipLines) != 3 || tipLines[0] != wantReason || tipLines[1] != "mode: enforce (deny by default, kept)" {
		t.Fatalf("kept+inactive: unexpected tooltip lines %#v", tipLines)
	}
}

func TestStatusHookActiveUnknownAndNoneUnchanged(t *testing.T) {
	asRootPeer(t)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	baseline := mustRunStatus(t, "status", "-api", s.Path())

	for _, cmd := range []string{"hook active", "hook unknown", "hook none"} {
		if err := s.Do(cmd); err != nil {
			t.Fatal(err)
		}
		if got := mustRunStatus(t, "status", "-api", s.Path()); got != baseline {
			t.Fatalf("%s: got %#v, want baseline %#v", cmd, got, baseline)
		}
	}

	if err := s.Do("keep"); err != nil {
		t.Fatal(err)
	}
	keptBaseline := mustRunStatus(t, "status", "-api", s.Path())
	for _, cmd := range []string{"hook active", "hook unknown", "hook none"} {
		if err := s.Do(cmd); err != nil {
			t.Fatal(err)
		}
		if got := mustRunStatus(t, "status", "-api", s.Path()); got != keptBaseline {
			t.Fatalf("kept %s: got %#v, want baseline %#v", cmd, got, keptBaseline)
		}
	}
}
