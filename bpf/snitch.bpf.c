// snitchd: egress control at connect() time, in the kernel (BPF LSM).
// Phase 1 probe: observe only (never denies), reports who connects where.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

struct event {
	__u32 pid;
	__u32 ppid;
	__u64 exe_ino;   // program identity: inode + device of the executable
	__u32 exe_dev;
	__u32 daddr;     // IPv4 for now
	__u16 dport;
	__u16 family;
	__u8  proto;
	char  comm[16];
};

// keeps struct event in the object's BTF, so bpf2go can emit the Go type (-type event)
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct sockaddr_in sin = {};
	if (bpf_probe_read_kernel(&sin, sizeof(sin), address))
		return 0;
	if (sin.sin_family != AF_INET)
		return 0;  // IPv6 in the next step

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *t = bpf_get_current_task_btf();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	struct file *exe = BPF_CORE_READ(t, mm, exe_file);
	e->exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
	e->exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	e->daddr = sin.sin_addr.s_addr;
	e->dport = bpf_ntohs(sin.sin_port);
	e->family = AF_INET;
	e->proto = BPF_CORE_READ(sock, sk, sk_protocol);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;  // observe only
}
