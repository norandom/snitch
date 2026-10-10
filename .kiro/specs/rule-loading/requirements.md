# Requirements Document

## Introduction

`snitchd` already decides every outbound connection in the kernel, but the two rule maps it
consults are empty: the `programs` table (which executable is which program) and the `rules`
table (which program may reach which destination). This feature gives the operator a rules file
that `snitchd` loads into those maps, keeps current while executables and the file change, and
proves end to end on the dev VM that enforce mode denies what no rule allows while every
fail-safe still works.

Project description (input): rule-loading: snitchd loads a rules file into the BPF maps
(programs: exe path/glob → inode+dev; rules: program/family/proto/port/prefix → allow or deny),
re-resolves on change, and gets its first enforce test on the dev VM: deny-by-default trial with
allow curl → one private prefix only, EPERM elsewhere, kill switch on/off, SIGSTOP the daemon →
fail open after 15 s, all under a shell trap that resets mode and kill switch. Fail-safes 2–5
apply; mode switch only with the user's explicit go.

## Boundary Context

- **In scope**: a rules file read by `snitchd`; programs named by executable path or glob;
  rules by program, IP version, protocol, port and address prefix with an allow or deny
  verdict; loading at start, reloading on file change, re-resolving executables that change;
  the program name in the event output; a learning mode that records observed connections as
  rule candidates in the same file format; a bounded enforce run; the enforce verification
  procedure on the dev VM.
- **Out of scope**: rules by domain name (needs the DNS tap, its own spec); rules by parent
  process or session ("started in the session" in the Python client); a persistent
  deny-by-default trial with deadline file and boot revert (its own spec, needed before
  `snitchd` becomes a boot service in enforce mode); the unix socket API and the TUI;
  per-rule byte counting; rule editing from the UI; learned rules by domain name (learning
  records addresses until the DNS tap exists) and automatic promotion of learned rules into the
  live rules file (the operator reviews and merges).
- **Adjacent expectations**: the kernel program keeps its fixed decision order (kill switch,
  heartbeat, local network, rules, mode default) and its local-network allow list; this
  feature only fills the two rule maps and must not change that order. Fail-safe rules 2–5 of
  steering `fail-safes.md` are preconditions, not deliverables of this feature.

## Requirements

### Requirement 1: Rules file
**Objective:** As the operator, I want to write programs and rules in one file, so that egress
policy is configuration I can read, review and deploy like any other config.

#### Acceptance Criteria
1. The rules file shall declare programs, each with a name and one or more executable paths or
   globs, and rules, each naming a program or "any program", a destination address prefix
   (IPv4 or IPv6), an optional protocol (tcp, udp or any), an optional port (or any) and a
   verdict (allow or deny).
2. When `snitchd` starts, the `snitchd` daemon shall read the rules file from the location given
   on its command line, with a documented default location when none is given.
3. If the rules file does not exist at start, the `snitchd` daemon shall start with empty rule
   maps and report that no rules are loaded.
4. If the rules file contains a syntax error or a rule that references an undeclared program,
   an invalid prefix, an invalid port, or an unknown protocol, the `snitchd` daemon shall refuse
   to start and shall report the file, line and reason.
5. The rules file shall allow a comment on any line, so that the operator can document why a
   rule exists.

### Requirement 2: Programs resolved to executables
**Objective:** As the operator, I want to name programs by path or glob, so that rules survive
versioned installs and the kernel still matches on the executable's identity.

#### Acceptance Criteria
1. When the rules are loaded, the `snitchd` daemon shall resolve every executable path and
   every glob match to the identity the kernel sees for that file (inode and device), and
   shall map each resolved file to its program.
2. The `snitchd` daemon shall match a program on any filesystem the executable may live on,
   including overlay, btrfs and bind-mounted paths, with the same result the kernel reports in
   its events for that executable.
3. If a declared path does not exist or a glob matches nothing, the `snitchd` daemon shall
   load the remaining programs, shall report the unresolved entry by name, and shall keep the
   program's rules so they take effect once the executable appears.
4. When several paths or glob matches belong to one program, the `snitchd` daemon shall treat a
   connection from any of them as that program.
5. If a path is a symbolic link, the `snitchd` daemon shall resolve the link target, because
   the kernel reports the executable that actually runs.
6. The `snitchd` daemon shall report any executable that resolves to two different programs as
   a configuration error with both program names.

### Requirement 3: Rules loaded into the kernel
**Objective:** As the operator, I want every rule in the file to decide connections exactly as
written, so that the kernel's verdicts match my intent.

#### Acceptance Criteria
1. When the rules are loaded, the `snitchd` daemon shall make every rule effective for the
   kernel's decision, keyed by program, IP version, protocol, port and address prefix.
2. While a program-specific rule and an any-program rule both match a connection, the kernel
   program shall apply the program-specific rule.
3. While several rules for the same program match a connection, the kernel program shall apply
   the one with the exact protocol and port before the one with protocol only before the one
   with any protocol, and within the same specificity the longest address prefix.
4. When a rule names an IPv4 prefix, the `snitchd` daemon shall make it effective for IPv4
   destinations and for IPv4-mapped IPv6 destinations.
5. When a rule names a deny verdict, the kernel program shall deny the matching connection
   with "operation not permitted" in both monitor and enforce mode.
6. The `snitchd` daemon shall report, after loading, how many programs resolved, how many
   executables are mapped and how many rules are effective.

### Requirement 4: Rules stay current
**Objective:** As the operator, I want changes to the rules file and to installed executables
to take effect without restarting the daemon, so that an upgrade of a tool does not silently
turn its rules off.

#### Acceptance Criteria
1. When the rules file is modified, the `snitchd` daemon shall apply the new rules within
   5 seconds, without restart and without a window in which no rules are effective.
2. If a modified rules file is invalid, the `snitchd` daemon shall keep the previously
   effective rules, shall report the error with file, line and reason, and shall keep running.
3. When an executable named by a path or glob is replaced, added or removed, the `snitchd`
   daemon shall update the program mapping within 10 seconds, so that the new file is matched
   and the old identity is no longer matched.
4. When the operator sends the reload signal (SIGHUP), the `snitchd` daemon shall reload the
   rules file and re-resolve all executables immediately.
5. When rules are reloaded, the `snitchd` daemon shall report the same summary as at start
   (Requirement 3.6).

### Requirement 5: Events name the program
**Objective:** As the operator, I want each reported decision to show the configured program
name and the rule that applied, so that I can read the verdict stream during the enforce test
and later in the TUI.

#### Acceptance Criteria
1. When a connection is decided for a mapped executable, the `snitchd` daemon shall print the
   program's configured name with the event.
2. When a connection is decided for an executable no program maps, the `snitchd` daemon shall
   print the executable path (as today) and mark the program as unknown.
3. When a verdict comes from a rule, the `snitchd` daemon shall print which rule applied
   (program, prefix, protocol, port, verdict), so the operator can trace a deny to its line.

### Requirement 6: Bounded enforce mode
**Objective:** As the operator, I want enforce mode to be impossible to leave on by accident
in this phase, so that a wrong rule cannot lock me out (fail-safe 5).

#### Acceptance Criteria
1. If enforce mode is requested without a bounded run duration, the `snitchd` daemon shall
   refuse to start and shall say why.
2. While enforce mode is active and the run duration elapses, the `snitchd` daemon shall exit,
   detaching the kernel programs so that every connection is allowed again.
3. When `snitchd` exits for any reason, including a crash, the kernel shall allow every
   connection (programs detached; the pinned control and kill maps persist).
4. The `snitchd` daemon shall never alter the kill switch value at start or exit (fail-safe 4:
   a set kill switch survives a restart until the operator clears it).

### Requirement 7: Enforce verification on the dev VM
**Objective:** As the operator, I want a repeatable test that proves rules and all fail-safes
work together in enforce mode, so that I trust the daemon before it ever runs as a service.

#### Acceptance Criteria
1. The verification procedure shall run `snitchd` in enforce mode with a bounded duration under
   a shell trap that resets the mode and clears the kill switch on any exit, and shall be
   started only after the operator's explicit go in that session.
2. While enforce mode is active with a rules file that allows the curl program to a single
   public address prefix (and the operator's own session tooling to anywhere) and nothing
   else, when curl connects to an address inside that prefix, the connection shall succeed and
   the daemon shall report an allow by rule for the curl program.
3. While enforce mode is active with that rules file, when curl connects to a public address
   outside that prefix, curl shall fail with "operation not permitted" and the daemon shall
   report a default deny for the curl program.
4. While enforce mode is active, when the operator sets the kill switch, the previously denied
   curl connection shall succeed; when the operator clears it, the same connection shall fail
   again.
5. While enforce mode is active, when the daemon is stopped with SIGSTOP, the previously
   denied curl connection shall succeed after at most 15 seconds; when the daemon is resumed
   with SIGCONT, the same connection shall fail again within one heartbeat interval.
6. While enforce mode is active, the operator's RDP session and an SSH connection from the
   local network shall stay up and a new connection from a program without any rule to a
   local-network address shall succeed (the built-in local-network allow, not a rule).
7. When the procedure ends for any reason, the mode shall be monitor, the kill switch shall be
   clear, and the daemon shall be gone, and the procedure shall print each of these facts.
8. The verification procedure shall be kept in the repository so that it can be re-run after
   later changes to the kernel program or the loader.

### Requirement 8: Loader testable without root
**Objective:** As the maintainer, I want the file parsing, executable resolution and map
encoding verified by ordinary tests, so that CI catches regressions without a kernel.

#### Acceptance Criteria
1. The `snitchd` build shall include tests for parsing valid and invalid rules files that run
   without root and without loading the kernel program.
2. The `snitchd` build shall include a test that the device identity computed for a file
   equals what the kernel reports for the same file, verifiable on the dev VM against a real
   event.
3. The `snitchd` build shall include tests for the rule precedence of Requirement 3 at the
   level of the encoded entries (which key is produced for which rule).

### Requirement 9: Learning mode
**Objective:** As the operator, I want the daemon to record what programs actually connect to
while nothing is blocked, so that my first rules file is built from observed behaviour I review,
not written blind before the enforce trial.

#### Acceptance Criteria
1. Where learning mode is enabled, the `snitchd` daemon shall run as monitor mode (every
   connection allowed and reported) and shall additionally record each observed connection
   that no rule already covers and that is not a local-network destination.
2. If learning mode is requested together with enforce mode, the `snitchd` daemon shall refuse
   to start and shall say that learning never denies.
3. The `snitchd` daemon shall record a learned connection as the executable (resolved path, or
   the configured program name when one maps it), the destination address, the protocol and the
   port, and shall merge repeated observations of the same combination into one entry with a
   count, first seen and last seen.
4. When learning mode ends (duration elapsed or the daemon is signalled to stop), the `snitchd`
   daemon shall write the learned entries as a rules file: one program per distinct executable,
   one allow rule per distinct destination, protocol and port, every rule commented with its
   count and first and last seen time.
5. The `snitchd` daemon shall write the learned file to a location separate from the live rules
   file, given on the command line with a documented default, and shall never modify the live
   rules file itself.
6. If the learned file already exists when learning starts, the `snitchd` daemon shall read it
   and continue counting from it, so that learning can run over several sessions.
7. While learning mode is active, the `snitchd` daemon shall also write the learned file
   periodically (at most every 60 seconds when something changed), so that a crash does not
   lose a session's observations.
8. When the learned file is written, it shall be loadable as a rules file without edits
   (Requirement 1), so the operator's only step before an enforce trial is to review and
   merge it.
9. While learning mode is active, when the executable behind a connection has already exited
   when the daemon looks it up, the `snitchd` daemon shall still record the entry using the
   executable identity reported by the kernel and shall mark the path as unknown.
