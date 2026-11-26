package clienttest

import (
	"fmt"
	"strings"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

const defaultBaseTOML = `
[[program]]
name  = "curl"
paths = ["/usr/bin/curl"]

[[program]]
name  = "wget"
paths = ["/usr/bin/wget"]

[[program]]
name  = "claude"
paths = ["/home/*/.local/share/claude/versions/*"]

[[program]]
name  = "apt"
paths = ["/usr/lib/apt/methods/http", "/usr/lib/apt/methods/https"]

[[program]]
name  = "gh"
paths = ["/usr/bin/gh"]

[[program]]
name  = "git"
paths = ["/usr/bin/git"]

[[rule]]
program = "curl"
to      = "1.1.1.1/32"
proto   = "tcp"
port    = 443
verdict = "allow"
note    = "the enforce test's allowed address"

[[rule]]
program = "claude"
to      = "0.0.0.0/0"
verdict = "allow"

[[rule]]
program = "claude"
to      = "::/0"
verdict = "allow"

[[rule]]
program = "apt"
to      = "0.0.0.0/0"
proto   = "tcp"
port    = 80
verdict = "allow"

[[rule]]
program = "apt"
to      = "0.0.0.0/0"
proto   = "tcp"
port    = 443
verdict = "allow"

[[rule]]
program = "any"
to      = "203.0.113.0/24"
verdict = "deny"
note    = "TEST-NET-3"

[[rule]]
program = "gh"
to      = "github.com"
verdict = "allow"

[[rule]]
program = "git"
to      = "github.com"
proto   = "tcp"
port    = 443
verdict = "allow"

[[rule]]
program = "git"
to      = "github.com"
proto   = "tcp"
port    = 22
verdict = "allow"

[[rule]]
program = "wget"
to      = "1.1.1.1/32"
proto   = "tcp"
port    = 443
verdict = "allow"

[[rule]]
program = "curl"
to      = "example.com"
verdict = "allow"

[[rule]]
program = "any"
to      = "192.0.2.0/24"
verdict = "deny"
note    = "TEST-NET-1"

[[rule]]
program = "any"
to      = "198.51.100.0/24"
verdict = "deny"
note    = "TEST-NET-2"
`

func (s *StandIn) initRules(noRules bool) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	if noRules {
		s.base = &rules.File{Name: baseFilePath}
	} else {
		f, err := rules.Parse(strings.NewReader(defaultBaseTOML), baseFilePath)
		contract.Ensure(err == nil, "clienttest: defaultBaseTOML must parse: "+fmt.Sprint(err))
		s.base = f
	}
	s.overlay = &rules.File{Name: overlayFilePath}
	merged, err := rules.Merge(s.base, s.overlay)
	contract.Ensure(err == nil, "clienttest: initial rules must merge: "+fmt.Sprint(err))
	s.merged = merged
	s.syncRuleCountsLocked()
}

// ClearRules drops all in-memory rules and programs and announces a reload.
func (s *StandIn) ClearRules() {
	s.fmu.Lock()
	s.base = &rules.File{Name: baseFilePath}
	s.overlay = &rules.File{Name: overlayFilePath}
	s.merged = &rules.File{Name: baseFilePath}
	st := s.syncRuleCountsLocked()
	s.fmu.Unlock()
	s.announce(st, reasonReloaded, true)
}

func (s *StandIn) syncRuleCountsLocked() api.Status {
	resolved, exes := 0, 0
	for _, p := range s.merged.Programs {
		if len(p.Paths) > 0 {
			resolved++
			exes += len(p.Paths)
		}
	}
	st := *s.facts.Load()
	st.Rules.Programs = len(s.merged.Programs)
	st.Rules.Resolved = resolved
	st.Rules.Executables = exes
	st.Rules.Rules = len(s.merged.Rules)
	s.facts.Store(&st)
	return st
}
