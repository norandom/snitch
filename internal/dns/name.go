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
	labelsMax = 16
	levelsMax = 8
	SlotsMax  = rules.NameSlots
	addrsMax  = 8
)

// covers compares names already normalized by rules.ParseName.
func covers(rule, name string) bool {
	return rule == name || strings.HasSuffix(name, "."+rule)
}

// key requires a bounded parsed name so a programming error cannot silently truncate a key.
func key(name string) [NameMax]byte {
	contract.Require(len(name) <= NameMax-2, "DNS name must fit the key with its leading dot and a zero byte")
	var key [NameMax]byte
	copy(key[:], "."+name)
	return key
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
