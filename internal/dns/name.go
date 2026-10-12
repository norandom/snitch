// Name helpers mirror the DNS tap's bounded keys without introducing another name parser.
package dns

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

const (
	NameMax   = 64
	LabelsMax = 16
	LevelsMax = 8
	SlotsMax  = 4
	AddrsMax  = 8
)

// Covers compares names already normalized by rules.ParseName.
func Covers(rule, name string) bool {
	return rule == name || strings.HasSuffix(name, "."+rule)
}

// Key requires a bounded parsed name so a programming error cannot silently truncate a key.
func Key(name string) [NameMax]byte {
	contract.Require(len(name) <= NameMax-2, "DNS name must fit the key with its leading dot and a zero byte")
	var key [NameMax]byte
	copy(key[:], "."+name)
	return key
}

// Suffixes follows the same bounded lookup order as the kernel.
func Suffixes(name string) []string {
	var out []string
	for len(out) < LevelsMax {
		out = append(out, name)
		_, rest, ok := strings.Cut(name, ".")
		if !ok {
			break
		}
		name = rest
	}
	return out
}

// keyName rejects malformed records before they can enter the parsed-name cache.
func keyName(key [NameMax]byte) (string, error) {
	end := bytes.IndexByte(key[:], 0)
	if end < 2 || key[0] != '.' {
		return "", fmt.Errorf("DNS record has invalid name key")
	}
	name := string(key[1:end])
	parsed, err := rules.ParseName(name)
	if err != nil || parsed != name {
		return "", fmt.Errorf("DNS record has invalid name key")
	}
	for _, b := range key[end:] {
		if b != 0 {
			return "", fmt.Errorf("DNS record has nonzero name padding")
		}
	}
	return name, nil
}
