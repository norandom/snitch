# Requirements Document

## Project Description (Input)
Make the missing `bpf` LSM impossible to overlook and let the deb fix it.

Found on the workstation chandali (2026-11-27, v1.1.0): the daemon attached its hooks and
logged them as working, the `decisions` counter stayed 0, and the UI showed a single `unknown`
row with no explanation. Cause: `CONFIG_BPF_LSM=y`, but `bpf` is not in the kernel's active
LSM list (`/sys/kernel/security/lsm`), so the hooks never fire.

1. The deb ships a GRUB drop-in `/etc/default/grub.d/snitch-lsm.cfg` that appends
   `lsm=<the host's current active list>,bpf`, computed when `update-grub` runs so no active
   LSM (AppArmor etc.) is dropped, and a `postinst` that runs `update-grub` when present and
   prints that a reboot is needed; on non-GRUB hosts it prints the line to add; remove/purge
   takes the drop-in away and regenerates. This deliberately changes the recorded
   "no maintainer scripts" promise in `docs/ci-debs.md` (operator decision, 2026-11-27: the
   deb runs `update-grub` itself).
2. `snitchd` detects at startup whether `bpf` is in `/sys/kernel/security/lsm`, logs one plain
   line, and serves it as a field in the API status, distinguishing "not configured" from
   "configured, reboot pending". It never denies anything because of it; fail-safes unchanged.
3. Every client surface warns: the TUI shows a persistent warning instead of a healthy empty
   table, `snitch status` reports class `down` with the text in the tooltip, the tray gets a
   state with the attention flag, `snitchd status` prints a line.
4. README, `docs/daemon.md`, `docs/tray.md`, `docs/tui.md`, `docs/ci-debs.md`,
   `examples/api.md` and the deb smoke test are updated.

## Introduction

snitchd decides in the kernel through BPF LSM hooks. Those hooks only run when `bpf` is in the
kernel's active LSM list, and that list is fixed at boot. On a kernel built with BPF LSM
support but booted without `bpf` in the list (Ubuntu's default), the daemon starts, attaches,
logs its hooks and reports a healthy monitor mode, while it sees and decides nothing: the
overview shows one `unknown` row and nobody is told why. Found on chandali on 2026-11-27 with
v1.1.0.

This feature closes that gap from both ends. The package configures the next boot so that
`bpf` is active, and the daemon and every client say plainly, for as long as it is true, that
the kernel hook is inactive and what to do about it.

## Boundary Context

- **In scope**: detecting whether the kernel hook is active; the daemon's log line, its status
  verb and its API status; the warning in the terminal UI, the status-bar verb and the tray;
  refusing a deny-by-default trial that could not deny anything; the package's boot
  configuration for GRUB hosts on install, upgrade and removal, and its printed instruction on
  other hosts; documentation; tests without root, the package smoke test, and a check on
  chandali with the operator's go.
- **Out of scope**: configuring boot loaders other than GRUB (they get the instruction, not
  the change); rebooting the host; building or changing a kernel that lacks BPF LSM support;
  any change to the kernel programs, the rule engine, the maps or the fail-safes; the hosts
  deployed from the VM repository by pinned binary (they do not install the package, and the
  dev VM already boots with `bpf` active); tagging a release.
- **Adjacent expectations**: the API (daemon-api) gains one status fact and otherwise stays as
  documented in `examples/api.md`; clients older than this feature keep working against the
  new daemon and new clients keep working against an older daemon, which they treat as "not
  reported". The package (ci-debs) so far promised that nothing runs on install beyond
  unpacking; this feature replaces that promise with a narrower, stated one (operator
  decision, 2026-11-27). The tray (kde-tray) and the terminal UI (tui) keep their rule that
  they display the daemon's facts and never change a mode.

## Requirements

### Requirement 1: The daemon knows whether its kernel hook is active
**Objective:** As the operator, I want the daemon to find out at start whether the kernel will
call its hooks, so that a daemon that cannot see connections never passes for a working one.

#### Acceptance Criteria
1. When snitchd starts, the snitchd daemon shall determine whether `bpf` is in the kernel's
   active LSM list and record one of three hook states: active, inactive, or unknown (the list
   could not be read).
2. While the hook state is inactive, the snitchd daemon shall also record whether the next boot
   is configured to activate it (reboot pending) or not (not configured).
3. When snitchd starts with the hook inactive, the snitchd daemon shall log one line that says
   the kernel hook is inactive, that connections are neither seen nor blocked, and whether a
   reboot is pending or the boot configuration is missing.
4. When snitchd starts with the hook active, the snitchd daemon shall log that the hook is
   active in its existing start line or one line next to it.
5. While the hook state is inactive or unknown, the snitchd daemon shall keep running and keep
   serving its API, the DNS tap and the byte counters as before.
6. The snitchd daemon shall never deny a connection, change the mode, or touch the kill switch
   because of the hook state (fail-safes 2 to 5 unchanged; fail-safe 3 still means allow).
7. If the running kernel's build configuration shows it was built without BPF LSM support,
   then the snitchd daemon shall record the hook state as inactive and unsupported, and every
   surface of Requirements 2 and 4 to 6 shall say that no reboot can activate the hook on this
   kernel instead of asking for a reboot.

### Requirement 2: The hook state in the status verb and the API
**Objective:** As a client author and as the operator on a console, I want the hook state as a
fact of the daemon's status, so that every surface can show the same truth.

#### Acceptance Criteria
1. When a client requests the status, the snitchd API shall include the hook state (active,
   inactive, unknown), and while inactive whether a reboot is pending, and a one-sentence
   human-readable reason.
2. When the operator runs `snitchd status`, the snitchd status verb shall print one line for
   the kernel hook that names the state and, while inactive, the next step (reboot, or
   configure the boot loader).
3. While the hook state is inactive, the snitchd status verb shall exit with the same status
   it uses today for a running daemon, so scripts that test "is the daemon running" keep
   working.
4. If a client built before this feature reads the new status, then that client shall keep
   working unchanged.
5. If a client built with this feature reads a status that carries no hook state, then that
   client shall treat the hook state as not reported and shall show no hook warning.
6. The documentation of the API shall describe the hook state with one example per state.

### Requirement 3: No deny-by-default trial that cannot deny
**Objective:** As the operator, I want a trial refused while the kernel hook is inactive, so
that I never believe deny by default is on when nothing is enforced.

#### Acceptance Criteria
1. If a trial or a keep is requested while the hook state is inactive, then the snitchd daemon
   shall refuse it with a message that says the kernel hook is inactive and names the next
   step, and shall change nothing.
2. While the hook state is active or unknown, the snitchd daemon shall accept trial verbs as
   before.
3. If the daemon starts with the hook inactive while a kept enforce or an open trial is
   recorded, then the snitchd daemon shall leave those records as they are and shall report
   the hook warning ahead of the mode on every surface of Requirements 2 and 4 to 6.
4. The snitchd daemon shall accept `end` and `unkeep` in every hook state.

### Requirement 4: The terminal UI warns
**Objective:** As a user who starts `snitch`, I want a warning I cannot miss when the kernel
hook is inactive, so that an empty or `unknown`-only table is explained on the same screen.

#### Acceptance Criteria
1. While the daemon reports the hook state inactive, the snitch terminal UI shall show a
   persistent warning in the overview and in the egress graph that says connections are
   neither seen nor blocked and names the next step (reboot, or configure the boot loader).
2. While the warning is shown, the snitch terminal UI shall keep every other function working
   (navigation, time windows, the graph, quitting).
3. When the daemon reports the hook state active after a restart or a reboot, the snitch
   terminal UI shall remove the warning without a restart of the UI.
4. While the daemon reports the hook state unknown, the snitch terminal UI shall show a
   shorter notice that the kernel hook could not be checked.
5. The snitch terminal UI shall render the warning from the daemon's sanitised text and its
   own fixed wording only, within the existing 80x20 minimum size.

### Requirement 5: The status-bar verb warns
**Objective:** As a user with the shield in a status bar, I want the shield to stop looking
healthy while the kernel hook is inactive.

#### Acceptance Criteria
1. While the daemon reports the hook state inactive, `snitch status` shall print the class
   `down` and a tooltip whose first line says the kernel hook is inactive and names the next
   step.
2. While the daemon reports the hook state active, unknown or not reported, `snitch status`
   shall print what it prints today.
3. The `snitch status` verb shall keep exiting 0 and printing one line in every hook state.

### Requirement 6: The tray warns
**Objective:** As the operator on a Plasma desktop, I want the tray icon to show that snitch
is blind, so that I see it without opening anything.

#### Acceptance Criteria
1. While the daemon reports the hook state inactive, the snitch tray shall show a seventh
   state, "kernel hook inactive", with its own drawn icon that differs in shape from the six
   existing ones and reads on a light and on a dark panel.
2. The snitch tray shall rank the new state directly after "daemon not running" and before
   "kill switch set", and shall mark it as needing attention.
3. While the new state holds, the tooltip and the first menu row shall name it, and the menu
   shall carry a row that says whether a reboot is pending or the boot configuration is
   missing.
4. When the state changes to "kernel hook inactive", the snitch tray shall notify once, as it
   does for the other state changes for the worse.
5. The snitch tray shall keep its rule that it changes no mode and writes nothing except the
   rule of a clicked answer.

### Requirement 7: The package configures the next boot on GRUB hosts
**Objective:** As a user who installs the package, I want it to arrange for `bpf` to be active
after the next reboot, so that I do not have to learn about kernel parameters.

#### Acceptance Criteria
1. When the package is installed or upgraded on a host that boots through GRUB and whose
   kernel does not have `bpf` active, the snitch package shall configure the next boot so that
   the LSM list is the host's currently active list with `bpf` added, and shall regenerate the
   boot loader configuration.
2. The snitch package shall never remove or reorder an LSM that is active on the host (for
   example AppArmor) and shall never write a fixed list of its own.
3. If the host's boot configuration already sets an LSM list of the administrator's own, then
   the snitch package shall leave that setting alone and shall print the exact addition
   (`bpf`) the administrator needs to make.
4. If `bpf` is already active on the host without the package's setting, then the snitch
   package shall add nothing to the boot configuration.
5. If the active LSM list cannot be read when the boot loader configuration is generated (a
   chroot, an image build), then the snitch package shall add nothing rather than guess.
6. When the package changed the next boot's configuration, the snitch package shall print that
   a reboot is needed for snitch to see connections.
7. If the host does not boot through GRUB, then the snitch package shall change no boot
   configuration and shall print the kernel parameter to add by hand.
8. If regenerating the boot loader configuration fails or the tool is absent, then the snitch
   package shall still install successfully and shall print what was not done.
9. When the package is removed or purged, the snitch package shall take its boot setting away
   and regenerate the boot loader configuration, so the next boot uses the kernel's own
   default again.
10. The snitch package shall run nothing else on install, upgrade or removal: it shall not
    enable or start a unit, write the operator file, or touch rules beyond what dpkg does with
    the shipped sample. Amended by operator decision 2026-11-28: on a fresh install (or an
    upgrade from a version before 1.2.0) the package shall enable `snitchd.service` together
    with `snitchd-trial-boot.service` at boot, never one without the other; when
    `snitchd.service` is running at configure, it shall restart it so an upgrade takes effect
    now; on removal it shall stop and disable both. It shall still never start a stopped unit
    on install, and a failed enable, restart, stop or disable shall be printed without
    failing the operation.
11. The snitch package shall remain installable with no dependencies and shall pass the
    package checker at the committed threshold on both supported distributions.
12. Before adding `bpf` to the next boot's configuration, the snitch package shall verify that
    every installed kernel the boot loader offers is built with BPF LSM support; if any is not,
    or support cannot be determined for one, then the snitch package shall add nothing and
    shall print which kernel and why, because the setting applies to every boot entry.

### Requirement 8: Documentation and verification
**Objective:** As a user and as a maintainer, I want the requirement, the automation and its
limits written down and tested, so that this cannot go unnoticed again.

#### Acceptance Criteria
1. The README shall say that the package configures GRUB hosts and that a reboot is needed
   after the first install, how to check the state, and what to do on other boot loaders.
2. The daemon, tray, terminal UI and package documents shall each describe the hook state as
   their surface shows it, and the package document shall replace its "nothing runs on
   install" statement with the new promise of Requirement 7.
3. The test suite shall cover, without root and without changing the test host's boot
   configuration: the three hook states and reboot pending; the boot setting for every case of
   Requirement 7 (1 to 5); every client surface for inactive, unknown and not reported; and
   the trial refusal.
4. The package smoke test shall prove on both supported distributions that install, upgrade,
   removal and purge succeed without a boot loader present and print the stated message, that
   the boot setting is laid and taken away again, and that no unit is enabled.
5. The check on chandali shall be run by the operator, never by an agent with root: after the
   install and a reboot the hook state is active and the overview shows programs with
   destinations; before the reboot every surface shows the warning.
