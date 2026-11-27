package clienttest_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/client/clienttest"
)

func startTestClient(t *testing.T, path string) <-chan client.Msg {
	t.Helper()
	msgs := make(chan client.Msg, 256)
	cfg := client.Config{
		Path: path,
		Dial: func(ctx context.Context, p string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", p)
		},
		Sink:       func(m client.Msg) { msgs <- m },
		Log:        func(string) {},
		Now:        time.Now,
		Poll:       20 * time.Millisecond,
		Gap:        5 * time.Millisecond,
		AnswerWait: 300 * time.Millisecond,
		BackoffMin: 20 * time.Millisecond,
		BackoffMax: 200 * time.Millisecond,
	}
	c := client.New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Job()(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("client job ended with %v, want context.Canceled", err)
		}
	})
	return msgs
}

func waitFacts(t *testing.T, msgs <-chan client.Msg, match func(api.Status) bool) api.Status {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case m := <-msgs:
			if f, ok := m.(client.Facts); ok && match(f.Status) {
				return f.Status
			}
		case <-deadline:
			t.Fatal("timed out waiting for matching Facts")
			return api.Status{}
		}
	}
}

func TestHookDefaultIsNotReported(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	if st := s.Facts(); st.Hook != nil {
		t.Fatalf("default Hook = %+v, want nil", st.Hook)
	}
}

func TestSetHookClonesAndClears(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	in := &api.HookStatus{State: api.HookInactive, Pending: true, Reason: "custom"}
	s.SetHook(in)
	in.State, in.Pending, in.Reason = api.HookActive, false, "mutated"

	got := s.Facts().Hook
	if got == nil || *got != (api.HookStatus{State: api.HookInactive, Pending: true, Reason: "custom"}) {
		t.Fatalf("Hook after SetHook + caller mutation = %+v", got)
	}
	s.SetHook(nil)
	if got := s.Facts().Hook; got != nil {
		t.Fatalf("Hook after SetHook(nil) = %+v, want nil", got)
	}
}

func TestDoHookCommands(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	cases := []struct {
		cmd  string
		want *api.HookStatus
	}{
		{"hook active", &api.HookStatus{State: api.HookActive, Reason: "kernel hook active"}},
		{"hook inactive", &api.HookStatus{State: api.HookInactive,
			Reason: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked"}},
		{"hook pending", &api.HookStatus{State: api.HookInactive, Pending: true,
			Reason: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked"}},
		{"hook unknown", &api.HookStatus{State: api.HookUnknown,
			Reason: "kernel hook not checked: the kernel's LSM list could not be read"}},
		{"hook none", nil},
	}
	for _, tc := range cases {
		if err := s.Do(tc.cmd); err != nil {
			t.Fatalf("%q: %v", tc.cmd, err)
		}
		got := s.Facts().Hook
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Fatalf("%q: got %+v, want %+v", tc.cmd, got, tc.want)
		}
	}
}

func TestDoHookRejectsInvalidArgs(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	if err := s.Do("hook active"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"hook", "hook bogus", "hook active extra", "hook pending now"} {
		if err := s.Do(bad); err == nil {
			t.Errorf("%q: expected error, got nil", bad)
		}
	}
	if got := s.Facts().Hook; got == nil || got.State != api.HookActive {
		t.Fatalf("Hook changed after invalid commands: %+v", got)
	}
}

func TestConnectedClientReceivesHookFacts(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	msgs := startTestClient(t, s.Path())
	st := waitFacts(t, msgs, func(st api.Status) bool { return st.Running })
	if st.Hook != nil {
		t.Fatalf("initial Hook = %+v, want nil", st.Hook)
	}

	if err := s.Do("hook pending"); err != nil {
		t.Fatal(err)
	}
	want := api.HookStatus{
		State:   api.HookInactive,
		Pending: true,
		Reason:  "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
	}
	st = waitFacts(t, msgs, func(st api.Status) bool { return st.Hook != nil && *st.Hook == want })
	if st.Hook == nil || *st.Hook != want {
		t.Fatalf("Hook after pending = %+v, want %+v", st.Hook, want)
	}

	if err := s.Do("hook none"); err != nil {
		t.Fatal(err)
	}
	st = waitFacts(t, msgs, func(st api.Status) bool { return st.Hook == nil })
	if st.Hook != nil {
		t.Fatalf("Hook after none = %+v, want nil", st.Hook)
	}
}
