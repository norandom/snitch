# Fail-safes (design constraints, not options)

Deny by default with Little Snitch cut the operator's RDP and SSH on 2026-10-09; recovery took a
reboot and the hypervisor console. Every spec, design and task in this repo is checked against
these five rules. They are not features to schedule; a change that weakens one is wrong.

## The rules

1. Egress decisions only. Nothing decides on `accept()` or inbound traffic; inbound RDP and SSH are never in scope. The DNS tap reads answers addressed to this host's own sockets, alters nothing, and can only add allow entries.
2. **The local network is allowed inside the BPF program**, not by a rule anyone can delete:
   RFC 1918, link-local 169.254/16, loopback, `fc00::/7`, `fe80::/10`, `::1`. The check runs
   before the rule lookup.
3. **Heartbeat, fail open.** The daemon writes a monotonic timestamp into the pinned `control`
   map every 2 s. Stale for 15 s (daemon wedged) or absent (daemon never started) means allow
   everything. Links are not pinned: a dead daemon detaches the programs entirely.
4. **Kill switch from a serial console**, root, no network or daemon needed:
   `bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0`
   (`value 0 0 0 0` clears it). A daemon restart must keep it until cleared.
5. **Deny mode only as a timed trial with a boot revert.** The deadline is a file, not a timer
   in memory (the shape of `snitch-trial`: a timer checks it, a boot unit ends an open trial
   before anything enforces). `--keep` is an explicit second step.

## Working rules on the development VM

- Never switch a mode or deploy anything that can cut the operator's RDP session without
  asking first, while they have the hypervisor console open as a way back.
- Test with `-duration`, and reset mode and kill switch in a shell `trap`.
- Test LAN SSH and the RDP session itself after a change, not just outbound internet.
- A revert must survive a reboot (a lockout usually ends in one).

## How specs use this

- Requirements for anything touching the kernel program, the mode, the maps or the service
  units cite the rule numbers they affect and state how the behaviour is preserved.
- Design reviews ask: "If the daemon dies, hangs, or loads garbage rules, what does the
  kernel do?" The answer must be "allow".
- Task lists for enforce-mode work include the trap-protected test and the revert.

---
_updated 2026-10-10: bootstrapped from CLAUDE.md and the firewall-lockout memory_
