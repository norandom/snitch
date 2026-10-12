// Recompile must preserve failed deletes while replacing pending obsolete puts.
package main

import (
	"errors"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

func TestRecompileRetriesPendingDelete(t *testing.T) {
	f := recompileFixture()
	stray := rules.RuleKey{Port: 999}
	f.live[stray] = rules.RuleVal{Id: 1, Verdict: uint8(rules.Allow)}
	attempts := 0
	f.s.rules.del = func(k any) error {
		if k != stray {
			t.Fatalf("unexpected delete %v", k)
		}
		attempts++
		if attempts < 3 {
			return errors.New("delete failed")
		}
		delete(f.live, stray)
		return nil
	}
	f.s.queue(nil, []rules.RuleKey{stray})
	f.s.flush(f.snap)
	f.s.recompile(f.snap)
	f.s.flush(f.snap)
	if attempts != 3 || len(f.live) != 0 || len(f.s.pending) != 0 {
		t.Fatalf("attempts %d live %v pending %v", attempts, f.live, f.s.pending)
	}
}

func TestContractHandleNeedsAnAccessor(t *testing.T) {
	f := newReaderFixture()
	f.s.current = nil
	contracttest.Panics(t, contract.Precondition, func() { f.s.handle(readerRecord()) })
}
