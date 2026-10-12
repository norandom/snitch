// snitchd's DNS tap observes resolver traffic and compiles allow entries from answers.
//
// Two cgroup_skb programs:
//   dns_query  (egress)  UDP to port 53 of a configured resolver: remember {socket cookie, id}
//                        -> question name, so the answer can be matched to the question (Req 1.3).
//   dns_answer (ingress) UDP from port 53 of a configured resolver, delivered to a socket of this
//                        host: parse the answer, match the question name and its suffixes against
//                        the `domains` map, write allow entries for every A/AAAA into the `rules`
//                        LPM trie (same key as snitchd), and mirror the answer to user space.
// Both programs return 1 on every path: nothing here can drop or delay a datagram.
// Only verdict 1 is written. BPF_NOEXIST never overwrites a file rule.
// A full ring buffer means no insert, so every insert can be mirrored to user space.
//
// Verifier shape (measured on 7.2.6, see the probe report): one bpf_loop only, a step machine
// over the answer section that compiles each address where it is found; a branch-free SWAR
// lowercase; the ring buffer record reserved before the walk so addresses never sit on the
// stack. Two consecutive bpf_loop calls or a byte-wise lowercase state machine blow the budget.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_UDP 17
#define DNS_PORT 53
// errno.h is not available in the BPF include path.
#define EEXIST 17

// Bounds chosen for the verifier. A name that does not fit is not learned (counted).
#define NAME_MAX 64     // bytes of a name key: ".api.github.com" style, lowercase, zero padded right
#define LABELS_MAX 16   // labels walked per name (question and answer owner names)
#define RR_MAX 32       // answer records walked
#define ADDRS_MAX 8     // A/AAAA records collected per answer
#define LEVELS_MAX 8    // suffixes tried: name, then dropping one leading label at a time
#define SLOTS_MAX 4     // rules per domain entry
#define STEPS_MAX (RR_MAX * (LABELS_MAX + 1))  // bpf_loop iterations: one label or one RR each

char LICENSE[] SEC("license") = "GPL";

// --- snitchd's trie key and value, byte for byte (bpf/snitch.bpf.c) ---
struct rule_key {
	__u32 prefixlen;
	__u32 program;
	__u8  family;
	__u8  proto;
	__u16 port;
	__u8  addr[16];
};

struct rule_val {
	__u8  verdict;     // 1 allow, 2 deny
	__u8  pad[3];
	__u32 id;
};

// A domain entry: the key is the lowercase name with a '.' before every label, left aligned,
// zero padded ("\x2egithub\x2ecom" for github.com). The suffix of a question name at label k is
// the same bytes starting at that label's dot, so one key layout serves names and suffixes.
struct domain_key {
	__u8 name[NAME_MAX];
};

struct domain_slot {
	__u32 program;     // 0 = any
	__u8  proto;       // 0 = any
	__u8  pad;
	__u16 port;        // 0 = any
	__u32 id;          // rule id, 0 = empty slot
};

struct domain_val {
	struct domain_slot slot[SLOTS_MAX];
};

struct resolver_key {
	__u8 addr[16];     // v4 in addr[0..3], rest 0 (snitchd's convention)
};

// Question seen on egress, keyed by the sending socket and the DNS id: glibc sends A and AAAA
// from one socket in parallel, so the cookie alone is not enough.
struct q_key {
	__u64 cookie;
	__u16 id;
	__u16 pad;
	__u32 pad2;
};

struct q_val {
	__u8  qname[NAME_MAX];
	__u64 ns;
};

// Ring buffer record: the answer as the kernel saw it, so the daemon can mirror the trie.
// bpf2go rejects a struct named dns_answer because it shares the program function name.
struct dns_answer_record {
	__u8  qname[NAME_MAX];
	__u32 ttl;          // smallest TTL of the collected records
	__u8  n;            // addresses collected
	__u8  pad[3];
	__u8  family[ADDRS_MAX];
	__u8  addrs[ADDRS_MAX][16];
	// Slots inserted for this answer, indexed by lvl*SLOTS_MAX+s; zero id is unused.
	// The same slots apply to every address.
	struct domain_slot slots[LEVELS_MAX * SLOTS_MAX];
};

// These indices are the user-space stats ABI; keep exists before update_fail.
enum dns_stat {
	ST_SEEN = 0,        // UDP datagrams from port 53
	ST_NOT_RESOLVER,    // ... from an address not in `resolvers`
	ST_NOT_ANSWER,      // not QR=1 / truncated / rcode != 0 / qdcount != 1
	ST_NO_QUESTION,     // no matching question record for (cookie, id, qname)
	ST_NAME_TOO_LONG,   // name beyond NAME_MAX/LABELS_MAX or compression in the question
	ST_PARSED,          // answers walked
	ST_UPDATES,         // trie entries written
	ST_EXISTS,          // an existing trie entry was preserved
	ST_UPDATE_FAIL,     // bpf_map_update_elem errors (trie full ...)
	ST_QUERIES,         // questions recorded on egress
	ST_RINGBUF_FULL,    // answer not mirrored (and not compiled)
	ST_MAX
};

// Set only by root tests through CollectionSpec.Variables, never by the daemon.
const volatile __u32 test_skip_question = 0;

// Unused pointers retain BTF for every struct read by Go. Rules use rules.RuleKey/RuleVal.
const struct domain_slot *unused_domain_slot __attribute__((unused));
const struct resolver_key *unused_resolver_key __attribute__((unused));
const struct domain_key *unused_domain_key __attribute__((unused));
const struct domain_val *unused_domain_val __attribute__((unused));
const struct dns_answer_record *unused_dns_answer_record __attribute__((unused));
const struct q_key *unused_q_key __attribute__((unused));
const struct q_val *unused_q_val __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct resolver_key);
	__type(value, __u32);
} resolvers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct domain_key);
	__type(value, struct domain_val);
} domains SEC(".maps");

// Shared through MapReplacements; cilium checks the spec against the main object.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__type(key, struct rule_key);
	__type(value, struct rule_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct q_key);
	__type(value, struct q_val);
} questions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} dns_answers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
} dns_stats SEC(".maps");

static __always_inline void bump(__u32 i)
{
	__u64 *c = bpf_map_lookup_elem(&dns_stats, &i);
	if (c)
		__sync_fetch_and_add(c, 1);
}

// Packet access uses bpf_skb_load_bytes. Dynptr was rejected for stack size.
struct pkt {
	struct __sk_buff *skb;
};

static __always_inline int pkt_init(struct pkt *p, struct __sk_buff *skb)
{
	p->skb = skb;
	return 0;
}

static __always_inline int rd(struct pkt *p, __u32 off, void *dst, __u32 len)
{
	return bpf_skb_load_bytes(p->skb, off, dst, len);
}

struct l4 {
	struct resolver_key peer;  // source on ingress, destination on egress: the resolver candidate
	__u16 sport;
	__u16 dport;
	__u16 dns_off;     // offset of the DNS header from skb->data (the network header)
	__u8  family;
};

// skb->data is the network header in cgroup_skb (both directions). UDP only; fragments and IPv6
// extension headers are not followed (the datagram is then not learned from).
static __always_inline int parse_l34(struct pkt *p, struct l4 *l, int peer_is_src)
{
	__u16 proto = bpf_ntohs((__u16)p->skb->protocol);
	__u32 off;
	if (proto == ETH_P_IP) {
		struct iphdr ip;
		if (rd(p, 0, &ip, sizeof(ip)))
			return -1;
		if (ip.version != 4 || ip.protocol != IPPROTO_UDP || (ip.frag_off & bpf_htons(0x3fff)))
			return -1;
		off = (__u32)ip.ihl * 4;
		if (off < 20)
			return -1;
		__builtin_memcpy(l->peer.addr, peer_is_src ? &ip.saddr : &ip.daddr, 4);
		l->family = AF_INET;
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;
		if (rd(p, 0, &ip6, sizeof(ip6)))
			return -1;
		if (ip6.nexthdr != IPPROTO_UDP)
			return -1;
		off = sizeof(ip6);
		__builtin_memcpy(l->peer.addr, peer_is_src ? &ip6.saddr : &ip6.daddr, 16);
		l->family = AF_INET6;
	} else {
		return -1;
	}
	struct udphdr uh;
	if (rd(p, off, &uh, sizeof(uh)))
		return -1;
	l->sport = bpf_ntohs(uh.source);
	l->dport = bpf_ntohs(uh.dest);
	if (bpf_ntohs(uh.len) < sizeof(uh) + 12)
		return -1;
	l->dns_off = off + sizeof(uh);
	return 0;
}

struct dnshdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

// Reads the question name into buf[0..n) (buf must be 2*NAME_MAX and zeroed), lowercases it and
// turns every length byte into '.', so buf holds ".api.github.com" left aligned, zero padded;
// dots[k] is the offset of label k, i.e. where the suffix key for level k starts. Returns the
// number of labels, or 0 if the name does not fit NAME_MAX / LABELS_MAX or uses compression
// (never in a question from a sane resolver).
static __always_inline __u32 read_qname(struct pkt *p, __u32 off, __u8 *buf, __u8 *dots, __u32 *wire_len)
{
	__u32 n = 0, labels = 0;
	int done = 0;
	for (int i = 0; i < LABELS_MAX && !done; i++) {
		__u8 L;
		if (rd(p, off + n, &L, 1))
			return 0;
		if (L == 0) {
			done = 1;
		} else if (L & 0xC0) {
			return 0;
		} else {
			dots[i] = n;  // i < LABELS_MAX by the loop bound
			labels = i + 1;
			n += 1 + L;
			if (n >= NAME_MAX)
				return 0;
		}
	}
	if (!done)
		return 0;
	// The barrier keeps clang from dropping the range check it has proven: the verifier needs
	// to see len bounded right before the load (otherwise "invalid zero-sized read").
	__u32 len = n;
	asm volatile("" : "+r"(len));
	if (len == 0 || len >= NAME_MAX)
		return 0;
	if (rd(p, off, buf, len))
		return 0;
	*wire_len = len;
	// Lowercase, eight bytes at a time, no branch: a lane gets 0x20 or-ed in iff its byte is in
	// 'A'..'Z'. Length bytes are <= 63 < 'A' and stay. (A byte-wise loop with a compare costs the
	// verifier 30-66k instructions here; this costs ~100.)
	__u64 *w = (__u64 *)buf;
	for (int i = 0; i < NAME_MAX / 8; i++) {
		__u64 x = w[i];
		__u64 a = x & 0x7f7f7f7f7f7f7f7fULL;
		__u64 ge = a + 0x3f3f3f3f3f3f3f3fULL;          // bit 7 set iff byte >= 0x41
		__u64 gt = a + 0x2525252525252525ULL;          // bit 7 set iff byte >= 0x5b
		__u64 m = ge & ~gt & ~x & 0x8080808080808080ULL;
		w[i] = x | (m >> 2);
	}
	// Every length byte becomes a '.', so the key form equals what user space builds from the
	// rule's name (internal/dns Key) for any suffix the lookup starts at, and the daemon decodes
	// the record's name by splitting on '.'. Only the first LEVELS_MAX labels are lookup starts.
	for (int k = 0; k < LABELS_MAX; k++) {
		if (k >= labels)
			break;
		buf[dots[k] & (NAME_MAX - 1)] = '.';
	}
	return labels;
}

// --- answer walk: one bpf_loop, one step per iteration ---
struct walk {
	struct pkt p;
	struct dns_answer_record *rec;  // reserved ring buffer record; addresses land there, not on the stack
	__u32 off;               // current offset into the packet
	__u32 ancount;
	__u32 rr;                // answer records finished
	__u32 labels;            // of the question name
	__u8  in_owner;          // 1: skipping the owner name of the current RR; 0: at its fixed part
	__u8  err;
	__u8  dots[LABELS_MAX];  // offset of every label's length byte; lookups start at the first LEVELS_MAX
	__u8  buf[2 * NAME_MAX] __attribute__((aligned(8)));  // name key, 8-aligned for the u64 passes; twice NAME_MAX so buf + dots[k] covers NAME_MAX bytes
};

struct rr_fixed {
	__u16 type;
	__u16 class;
	__u32 ttl;
	__u16 rdlen;
} __attribute__((packed));

// One address -> allow entries for every slot of every matching suffix of the question name.
static __always_inline void compile_addr(struct walk *w, const __u8 *addr, __u8 family)
{
	struct rule_key k = {};
	struct rule_val val = { .verdict = 1 };
	k.family = family;
	k.prefixlen = 64 + (family == AF_INET ? 32 : 128);
	__builtin_memcpy(k.addr, addr, 16);
	for (int lvl = 0; lvl < LEVELS_MAX; lvl++) {
		if (lvl >= w->labels)
			break;
		__u32 start = w->dots[lvl] & (NAME_MAX - 1);
		struct domain_val *v = bpf_map_lookup_elem(&domains, w->buf + start);
		if (!v)
			continue;
		for (int s = 0; s < SLOTS_MAX; s++) {
			struct domain_slot *sl = &v->slot[s];
			if (!sl->id)
				continue;
			k.program = sl->program;
			k.proto = sl->proto;
			k.port = sl->port;
			val.id = sl->id;
			// Mirror the slot the kernel attempts (EEXIST and failures included: the daemon
			// subtracts file keys and re-puts anyway); BPF_NOEXIST preserves existing file rules.
			w->rec->slots[lvl * SLOTS_MAX + s] = *sl;
			long err = bpf_map_update_elem(&rules, &k, &val, BPF_NOEXIST);
			if (err == -EEXIST)
				bump(ST_EXISTS);
			else if (err)
				bump(ST_UPDATE_FAIL);
			else
				bump(ST_UPDATES);
		}
	}
}

static __attribute__((noinline)) long walk_step(__u32 i, void *data)
{
	struct walk *w = data;
	__u32 off = w->off;
	if (w->rr >= w->ancount)
		return 1;
	if (w->in_owner) {
		// one label of the owner name; a zero or a compression pointer ends it
		__u8 L;
		if (rd(&w->p, off, &L, 1)) {
			w->err = 1;
			return 1;
		}
		if (L == 0) {
			w->off = off + 1;
			w->in_owner = 0;
		} else if ((L & 0xC0) == 0xC0) {
			w->off = off + 2;
			w->in_owner = 0;
		} else if (L & 0xC0) {
			w->err = 2;
			return 1;
		} else {
			w->off = off + 1 + L;
		}
		return 0;
	}
	struct rr_fixed f;
	if (rd(&w->p, off, &f, sizeof(f))) {
		w->err = 4;
		return 1;
	}
	off += sizeof(f);
	__u16 type = bpf_ntohs(f.type), rdlen = bpf_ntohs(f.rdlen);
	__u32 ttl = bpf_ntohl(f.ttl);
	struct dns_answer_record *rec = w->rec;
	__u32 n = rec->n;
	if (n < ADDRS_MAX && ((type == 1 && rdlen == 4) || (type == 28 && rdlen == 16))) {
		__u8 family = type == 1 ? AF_INET : AF_INET6;
		__u32 len = type == 1 ? 4 : 16;  // the verifier does not carry rdlen's two values through the ||
		__u8 *slot = rec->addrs[n];
		if (rd(&w->p, off, slot, len)) {
			w->err = 5;
			return 1;
		}
		rec->family[n] = family;
		rec->n = n + 1;
		if (ttl < rec->ttl)
			rec->ttl = ttl;
		compile_addr(w, slot, family);  // straight from the record: no 16-byte stack copy
	}
	// CNAME (5) and everything else: skipped by its rdlength
	w->off = off + rdlen;
	w->rr++;
	w->in_owner = 1;
	return 0;
}

SEC("cgroup_skb/ingress")
int dns_answer(struct __sk_buff *skb)
{
	struct walk w = {};
	if (pkt_init(&w.p, skb))
		return 1;
	struct l4 l = {};
	if (parse_l34(&w.p, &l, 1) || l.sport != DNS_PORT)
		return 1;
	bump(ST_SEEN);
	if (!bpf_map_lookup_elem(&resolvers, &l.peer)) {
		bump(ST_NOT_RESOLVER);
		return 1;
	}
	struct dnshdr h;
	if (rd(&w.p, l.dns_off, &h, sizeof(h)))
		return 1;
	__u16 flags = bpf_ntohs(h.flags);
	// QR=1, not truncated, rcode 0, exactly one question
	if (!(flags & 0x8000) || (flags & 0x0200) || (flags & 0x000f) || bpf_ntohs(h.qdcount) != 1) {
		bump(ST_NOT_ANSWER);
		return 1;
	}
	__u32 wire = 0;
	w.labels = read_qname(&w.p, l.dns_off + sizeof(h), w.buf, w.dots, &wire);
	if (!w.labels) {
		bump(ST_NAME_TOO_LONG);
		return 1;
	}
	if (!test_skip_question) {
		// the answer belongs to a question this socket sent: same cookie, id and name
		struct q_key qk = { .cookie = bpf_get_socket_cookie(skb), .id = h.id };
		struct q_val *q = bpf_map_lookup_elem(&questions, &qk);
		// A stale question cannot authorize learning from this answer; it is dropped so a
		// later answer with a reused id cannot match it either.
		if (!q || bpf_ktime_get_ns() - q->ns > 5000000000ULL) {
			if (q)
				bpf_map_delete_elem(&questions, &qk);
			bump(ST_NO_QUESTION);
			return 1;
		}
		__u64 diff = 0;
		for (int i = 0; i < NAME_MAX / 8; i++)
			diff |= ((__u64 *)q->qname)[i] ^ ((__u64 *)w.buf)[i];
		if (diff) {
			bump(ST_NO_QUESTION);
			return 1;
		}
		bpf_map_delete_elem(&questions, &qk);
	}

	struct dns_answer_record *rec = bpf_ringbuf_reserve(&dns_answers, sizeof(*rec), 0);
	if (!rec) {
		bump(ST_RINGBUF_FULL);
		return 1;
	}
	__builtin_memset(rec, 0, sizeof(*rec));
	__builtin_memcpy(rec->qname, w.buf, NAME_MAX);
	rec->ttl = 0xffffffff;
	w.rec = rec;
	w.off = l.dns_off + sizeof(h) + wire + 1 + 4;  // name, its zero, qtype, qclass
	w.ancount = bpf_ntohs(h.ancount);
	if (w.ancount > RR_MAX)
		w.ancount = RR_MAX;
	w.in_owner = 1;
	bpf_loop(STEPS_MAX, walk_step, &w, 0);
	bump(ST_PARSED);
	if (rec->n)
		bpf_ringbuf_submit(rec, 0);
	else
		bpf_ringbuf_discard(rec, 0);
	return 1;
}

// Egress: a question to a resolver. Records (cookie, id) -> name so the answer can be matched.
SEC("cgroup_skb/egress")
int dns_query(struct __sk_buff *skb)
{
	struct pkt p;
	if (pkt_init(&p, skb))
		return 1;
	struct l4 l = {};
	if (parse_l34(&p, &l, 0) || l.dport != DNS_PORT)
		return 1;
	if (!bpf_map_lookup_elem(&resolvers, &l.peer))
		return 1;
	struct dnshdr h;
	if (rd(&p, l.dns_off, &h, sizeof(h)))
		return 1;
	if ((bpf_ntohs(h.flags) & 0x8000) || bpf_ntohs(h.qdcount) != 1)
		return 1;
	struct q_val v = {};
	__u8 buf[2 * NAME_MAX] __attribute__((aligned(8))) = {};
	__u8 dots[LABELS_MAX] = {};
	__u32 wire = 0;
	if (!read_qname(&p, l.dns_off + sizeof(h), buf, dots, &wire))
		return 1;
	__builtin_memcpy(v.qname, buf, NAME_MAX);
	v.ns = bpf_ktime_get_ns();
	struct q_key k = { .cookie = bpf_get_socket_cookie(skb), .id = h.id };
	bpf_map_update_elem(&questions, &k, &v, BPF_ANY);
	bump(ST_QUERIES);
	return 1;
}
