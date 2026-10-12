// Name destinations share the rules parser and cannot introduce a persistent deny.
package main

import (
	"fmt"

	"github.com/norandom/snitch/internal/rules"
)

func (k *editKey) parseDestination(to string) error {
	var err error
	if k.to, err = rules.ParsePrefix(to); err == nil {
		return nil
	}
	k.name, err = rules.ParseName(to)
	return err
}

func (k editKey) destination() string {
	return (rules.Rule{To: k.to, Name: k.name}).Dest()
}

// Refuse before loading or mutating the overlay, including ad hoc program declarations.
func (k editKey) allowVerdict(to string, verdict rules.Verdict) error {
	if k.name != "" && verdict == rules.Deny {
		return fmt.Errorf("to %q: a deny by name is not supported (deny stays a timed trial)", to)
	}
	return nil
}
