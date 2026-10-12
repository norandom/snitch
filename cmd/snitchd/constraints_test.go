// These source constraints keep name learning passive: the daemon never resolves names.
package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDNSNeverResolvesNames(t *testing.T) {
	for _, dir := range []string{".", "../../internal/dns"} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			return checkNoResolver(t, path)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func checkNoResolver(t *testing.T, path string) error {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"net.Resolver", "LookupHost", "LookupIP", "DefaultResolver"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("%s references %s", path, forbidden)
		}
	}
	if regexp.MustCompile(`net\.Dial(?:Timeout)?\(\s*"[^"]+"\s*,\s*"[^"]*[a-zA-Z][^"]*"`).Match(raw) {
		t.Errorf("%s dials a hostname literal", path)
	}
	return nil
}
