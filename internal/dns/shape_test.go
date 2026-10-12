// These source checks pin the DNS tap's fail-open returns and allow-only writes.
package dns

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDNSFailSafeShape(t *testing.T) {
	source, err := os.ReadFile("../../bpf/dns.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	text := regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`).ReplaceAllString(string(source), "")
	for _, direction := range []string{"ingress", "egress"} {
		body := programBody(t, text, direction)
		returns := regexp.MustCompile(`\breturn\s+([^;]+);`).FindAllStringSubmatch(body, -1)
		if len(returns) == 0 {
			t.Fatal("program has no return")
		}
		for _, ret := range returns {
			if strings.TrimSpace(ret[1]) != "1" {
				t.Errorf("%s: unsafe return %s", direction, ret[1])
			}
		}
	}
	checkAllowWrites(t, text)
}

func checkAllowWrites(t *testing.T, text string) {
	t.Helper()
	updates := regexp.MustCompile(`bpf_map_update_elem\s*\(\s*&rules\s*,[^)]*\)`).FindAllString(text, -1)
	if len(updates) == 0 {
		t.Fatal("missing rules update")
	}
	for _, update := range updates {
		if !strings.HasSuffix(strings.TrimSpace(update), "BPF_NOEXIST)") {
			t.Errorf("rules update must use BPF_NOEXIST: %s", update)
		}
	}
	verdicts := regexp.MustCompile(`\bverdict\s*=\s*([^,;}]+)`).FindAllStringSubmatch(text, -1)
	if len(verdicts) == 0 {
		t.Fatal("missing allow verdict initialization")
	}
	for _, verdict := range verdicts {
		if strings.TrimSpace(verdict[1]) != "1" {
			t.Errorf("unsafe verdict: %s", verdict[1])
		}
	}
	if strings.Contains(text, "V_DENY") {
		t.Error("deny verdict in DNS tap")
	}
}

func programBody(t *testing.T, source, direction string) string {
	t.Helper()
	marker := `SEC("cgroup_skb/` + direction + `")`
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("missing %s program", direction)
	}
	rest := source[start+len(marker):]
	opening := strings.Index(rest, "{")
	if opening < 0 {
		t.Fatal("missing program body")
	}
	depth := 0
	for i := opening; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[opening+1 : i]
			}
		}
	}
	t.Fatal("unclosed program body")
	return ""
}
