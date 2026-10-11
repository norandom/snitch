package api

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// Design "Contracts": a request type the codec accepts but the verb table does not know is a
// bug in this package (TestServerVerbTableMatchesTheRequestTypes keeps the two in step); the
// dispatcher trips on it instead of answering nothing.
func TestContractDispatchNeedsAHandlerForEveryType(t *testing.T) {
	f := newFixture(t)
	run := verbs["status"]
	delete(verbs, "status")
	defer func() { verbs["status"] = run }()
	v := contracttest.Panics(t, contract.InvariantKind, func() { f.s.dispatch(&client{Client: &Client{}}, []byte(`{"type":"status"}`)) })
	if v.Msg != "every parsed request type has a handler" {
		t.Fatalf("message: %q", v.Msg)
	}
}

// A handler answering with anything but a Reply or an Error is a bug: stamped has no
// envelope for it.
func TestContractStampedNeedsAReplyOrAnError(t *testing.T) {
	contracttest.Panics(t, contract.Postcondition, func() { stamped(42, 1) })
	contracttest.Panics(t, contract.Postcondition, func() { stamped(nil, 1) })
}

// A table with no room at all cannot hold the entry it is asked to insert.
func TestContractInsertNeedsAPositiveMax(t *testing.T) {
	tb := NewTable(time.Now)
	tb.Max = 0
	contracttest.Panics(t, contract.Precondition, func() { tb.Observe(ev("a", "1.1.1.1", 1, "allow-rule")) })
}
