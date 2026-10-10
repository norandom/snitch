// snitchd: egress control at connect() time, in the kernel (BPF LSM).
//
// Fail-safe by construction, in this order:
//   kill switch  (pinned map "kill", flippable with bpftool from a serial console)  -> allow all
//   heartbeat    (the daemon writes a timestamp; stale for HEARTBEAT_MAX_NS)         -> allow all
//   local net    (RFC 1918, link-local, loopback; not a rule, cannot be deleted)      -> allow
//   rules        (program + destination prefix + proto/port -> allow/deny)
//   default      (monitor: allow and report; enforce: deny and report)
// Egress only: nothing here looks at accept() or inbound traffic.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define EPERM 1
#define HEARTBEAT_MAX_NS (15ULL * 1000000000ULL)

#define MODE_MONITOR 0
#define MODE_ENFORCE 1

enum verdict {
	V_ALLOW_MONITOR = 0,  // no rule, monitor mode
	V_ALLOW_RULE    = 1,
	V_DENY_RULE     = 2,
	V_DENY_DEFAULT  = 3,  // no rule, enforce mode
	V_ALLOW_LOCAL   = 4,
	V_ALLOW_STALE   = 5,  // heartbeat stale: fail open
	V_ALLOW_KILL    = 6,  // kill switch
};

char LICENSE[] SEC("license") = "GPL";

struct event {
	__u32 pid;
	__u32 ppid;
	__u64 exe_ino;
	__u32 exe_dev;
	__u32 program;     // id from the programs map, 0 = unknown
	__u8  addr[16];    // v4 in addr[0..3]
	__u16 dport;
	__u8  family;
	__u8  proto;
	__u8  verdict;
	__u8  hook;        // 0 connect, 1 sendmsg (unconnected UDP)
	char  comm[16];
	__u32 rule;        // id of the rule that decided, 0 = none
	char  path[256];   // exe path (bpf_d_path): only for unknown programs or with WANT_PATH
};

struct exe_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

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

#define FLAG_WANT_PATH 1  // daemon asks for the exe path on every event (learning mode)

struct control_state {
	__u64 heartbeat_ns;
	__u32 mode;
	__u32 flags;
};

const struct event *unused_event __attribute__((unused));
const struct rule_key *unused_rule_key __attribute__((unused));
const struct exe_key *unused_exe_key __attribute__((unused));
const struct control_state *unused_control __attribute__((unused));
const struct rule_val *unused_rule_val __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct exe_key);
	__type(value, __u32);
} programs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__type(key, struct rule_key);
	__type(value, struct rule_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct control_state);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} control SEC(".maps");

// Separate, pinned, one u32: `bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0`
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} kill SEC(".maps");

static __always_inline int local_v4(__u32 be)
{
	__u32 a = bpf_ntohl(be);
	return (a >> 24) == 10 || (a >> 24) == 127 || (a >> 20) == 0xac1 /* 172.16/12 */ ||
	       (a >> 16) == 0xc0a8 /* 192.168/16 */ || (a >> 16) == 0xa9fe /* 169.254/16 */;
}

static __always_inline int local_v6(const __u8 *a)
{
	if ((a[0] & 0xfe) == 0xfc) return 1;                  // fc00::/7
	if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 1;  // fe80::/10
	__u8 z = 0;
	for (int i = 0; i < 15; i++) z |= a[i];
	return z == 0 && a[15] == 1;                          // ::1
}

static __always_inline struct rule_val *lookup(__u32 program, __u8 family, __u8 proto, __u16 port, const __u8 *addr)
{
	struct rule_key k = {};
	k.prefixlen = 64 + (family == AF_INET ? 32 : 128);
	k.family = family;
	__builtin_memcpy(k.addr, addr, 16);
	// most specific first: exact proto+port, proto only, anything; for the program, then for any
	__u32 progs[2] = { program, 0 };
	for (int p = 0; p < 2; p++) {
		if (p == 1 && program == 0) break;
		k.program = progs[p];
		k.proto = proto; k.port = port;
		struct rule_val *v = bpf_map_lookup_elem(&rules, &k);
		if (v) return v;
		k.port = 0;
		v = bpf_map_lookup_elem(&rules, &k);
		if (v) return v;
		k.proto = 0;
		v = bpf_map_lookup_elem(&rules, &k);
		if (v) return v;
	}
	return NULL;
}

static __always_inline int decide(struct socket *sock, struct sockaddr *address, __u8 hook)
{
	struct sockaddr_in6 sa = {};
	if (bpf_probe_read_kernel(&sa, sizeof(sa), address))
		return 0;
	__u8 addr[16] = {};
	__u16 dport;
	__u8 family;
	if (sa.sin6_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&sa;
		__builtin_memcpy(addr, &in->sin_addr, 4);
		dport = bpf_ntohs(in->sin_port);
		family = AF_INET;
	} else if (sa.sin6_family == AF_INET6) {
		__builtin_memcpy(addr, &sa.sin6_addr, 16);
		dport = bpf_ntohs(sa.sin6_port);
		family = AF_INET6;
		// v4-mapped ::ffff:a.b.c.d is a v4 destination
		__u8 m = 0;
		for (int i = 0; i < 10; i++) m |= addr[i];
		if (m == 0 && addr[10] == 0xff && addr[11] == 0xff) {
			__builtin_memcpy(addr, addr + 12, 4);
			__builtin_memset(addr + 4, 0, 12);
			family = AF_INET;
		}
	} else {
		return 0;  // unix, netlink ...: not ours
	}

	__u8 verdict;
	__u32 rule = 0;
	__u32 zero = 0;
	__u32 *k = bpf_map_lookup_elem(&kill, &zero);
	struct control_state *c = bpf_map_lookup_elem(&control, &zero);
	__u64 now = bpf_ktime_get_ns();
	// the exe file as a trusted, acquired reference (kfunc): bpf_d_path needs a trusted
	// pointer, a walk through task->mm->exe_file is untrusted. Released at the end.
	struct task_struct *t = bpf_get_current_task_btf();
	struct file *exe = bpf_get_task_exe_file(t);
	struct exe_key ek = {};
	if (exe) {
		ek.ino = BPF_CORE_READ(exe, f_inode, i_ino);
		ek.dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	}
	__u32 *pid_p = bpf_map_lookup_elem(&programs, &ek);
	__u32 program = pid_p ? *pid_p : 0;
	__u8 proto = BPF_CORE_READ(sock, sk, sk_protocol);

	if (k && *k)
		verdict = V_ALLOW_KILL;
	else if (!c || c->heartbeat_ns == 0 || now - c->heartbeat_ns > HEARTBEAT_MAX_NS)
		verdict = V_ALLOW_STALE;
	else if (family == AF_INET ? local_v4(*(__u32 *)addr) : local_v6(addr))
		verdict = V_ALLOW_LOCAL;
	else {
		struct rule_val *r = lookup(program, family, proto, dport, addr);
		if (r) rule = r->id;
		if (r && r->verdict == 1) verdict = V_ALLOW_RULE;
		else if (r && r->verdict == 2) verdict = V_DENY_RULE;
		else verdict = c->mode == MODE_ENFORCE ? V_DENY_DEFAULT : V_ALLOW_MONITOR;
	}

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->ppid = BPF_CORE_READ(t, real_parent, tgid);
		e->exe_ino = ek.ino;
		e->exe_dev = ek.dev;
		e->program = program;
		__builtin_memcpy(e->addr, addr, 16);
		e->dport = dport;
		e->family = family;
		e->proto = proto;
		e->verdict = verdict;
		e->hook = hook;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		e->rule = rule;
		e->path[0] = 0;
		// the path costs a d_path walk: only where the daemon needs it
		if (exe && (program == 0 || (c && (c->flags & FLAG_WANT_PATH))))
			if (bpf_d_path(&exe->f_path, e->path, sizeof(e->path)) < 0)
				e->path[0] = 0;
		bpf_ringbuf_submit(e, 0);
	}
	if (exe)
		bpf_put_file(exe);
	return (verdict == V_DENY_RULE || verdict == V_DENY_DEFAULT) ? -EPERM : 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	return decide(sock, address, 0);
}

// Unconnected UDP (sendto with an address): the connect hook never sees it.
SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	struct sockaddr *name = BPF_CORE_READ(msg, msg_name);
	if (!name)
		return 0;  // connected socket: decided at connect()
	return decide(sock, name, 1);
}
