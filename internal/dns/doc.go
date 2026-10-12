// Package dns holds the pure Go side of the DNS tap. It performs no syscalls
// and uses no JSON; observation failures must leave traffic allowed.
// Its allowed internal dependencies are rules, bpf, and contract.
package dns
