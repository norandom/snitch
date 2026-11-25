// rules_abi.h: the one definition of the `rules` LPM trie key and value.
//
// snitch.bpf.c (the egress decision) reads the trie, dns.bpf.c (the DNS tap) writes allow
// entries into the same trie by map replacement, and the daemon loads the file rules into it.
// All three must agree byte for byte, so both programs include this header and neither defines
// the structures itself; each program keeps its own BTF reference for its generated Go type.
//
// Fail-safe: verdict 1 is allow, 2 is deny; the DNS tap writes only 1, so it can add allow
// entries and nothing else.
//
// Needs __u8/__u16/__u32: include after <vmlinux.h>.
#ifndef SNITCH_RULES_ABI_H
#define SNITCH_RULES_ABI_H

#include "contract.h"

// LPM key: the fixed part (program, family, proto, port) is always fully covered by prefixlen,
// the address prefix follows. proto 0 / port 0 mean "any"; program 0 means "any program".
struct rule_key {
	__u32 prefixlen;
	__u32 program;
	__u8  family;
	__u8  proto;
	__u16 port;
	__u8  addr[16];
};

// Trie value: the verdict and which rule it came from (for the event stream).
struct rule_val {
	__u8  verdict;     // 1 allow, 2 deny
	__u8  pad[3];
	__u32 id;
};

CONTRACT_SIZE(struct rule_key, 28);
CONTRACT_OFFSET(struct rule_key, prefixlen, 0);
CONTRACT_OFFSET(struct rule_key, program, 4);
CONTRACT_OFFSET(struct rule_key, family, 8);
CONTRACT_OFFSET(struct rule_key, proto, 9);
CONTRACT_OFFSET(struct rule_key, port, 10);
CONTRACT_OFFSET(struct rule_key, addr, 12);
// The fixed part between prefixlen and addr is the 64 bits every prefixlen covers first.
CONTRACT_CONST((__builtin_offsetof(struct rule_key, addr) -
		__builtin_offsetof(struct rule_key, program)) * 8 == 64,
	       "rule_key fixed part is 64 bits");

CONTRACT_SIZE(struct rule_val, 8);
CONTRACT_OFFSET(struct rule_val, verdict, 0);
CONTRACT_OFFSET(struct rule_val, pad, 1);
CONTRACT_OFFSET(struct rule_val, id, 4);

#endif // SNITCH_RULES_ABI_H
