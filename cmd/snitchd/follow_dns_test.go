// The record path is separate from API status: bounded flag runs never write it.
package main

import (
	"testing"

	"github.com/norandom/snitch/internal/status"
)

func TestFollowDNSRecordCarriesTap(t *testing.T) {
	x := newStatusFixture()
	x.w.dns = (*dnsState)(nil).recordLine
	x.tick(t)
	if got := x.writes[0].DNS; got != "off: unavailable" {
		t.Fatalf("record DNS: %q", got)
	}
	path := t.TempDir() + "/status"
	if err := status.Write(path, x.writes[0]); err != nil {
		t.Fatal(err)
	}
	rec, err := status.Read(path)
	if err != nil || rec.DNS != x.writes[0].DNS {
		t.Fatalf("round trip: %+v %v", rec, err)
	}
	x.w.dns = namedDNSState().recordLine
	x.tick(t)
	if got := x.writes[1].DNS; got != "on seen 42 ignored 10 cache 1 names 2 compiled 1" {
		t.Fatalf("on record DNS: %q", got)
	}
	x.w.dns = nil
	x.tick(t)
	if got := x.writes[2].DNS; got != "" {
		t.Fatalf("absent delegate: %q", got)
	}
	if jobs := (&daemon{}).modeJobs(); len(jobs) != 0 {
		t.Fatal("a flag daemon writes no record")
	}
}
