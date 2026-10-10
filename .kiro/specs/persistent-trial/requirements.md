# Requirements Document

## Project Description (Input)
persistent-trial: snitchd runs as a systemd service (monitor mode) and deny-by-default becomes
a timed trial that survives reboots in the safe direction.

- **Who**: the operator of the dev VM (later every fleet host) who wants snitchd always on and
  wants to try enforce mode without risking a lockout.
- **Current situation**: snitchd runs only by hand; enforce exists only as a bounded run
  (`-mode enforce` needs `-duration`) used by `scripts/enforce-test.sh`; the daemon refuses
  enforce without a duration; there is no service unit and no way to switch a running daemon's
  mode. The old Little Snitch trial (`snitch-trial`: a deadline file, a 30 s timer that reverts,
  a boot unit that ends an open trial before the daemon starts) has no counterpart.
- **What should change**: a systemd service for snitchd that starts in monitor mode at boot. A
  trial command puts the daemon into enforce for a chosen duration by writing a deadline file
  (not a timer in memory); the daemon follows the file (enforce while the deadline is in the
  future, monitor otherwise) and ends the trial itself at the deadline. At boot an open trial
  is ended before anything enforces (the daemon or a oneshot removes it). An explicit second
  step (keep) makes enforce persistent, and that persistence is also a file the operator can
  delete from a console. A status command shows mode, trial deadline, heartbeat age and the
  kill switch. The kill switch keeps working across restarts. Fail-safes 2–5 apply, and the
  mode switch is only ever tested on the dev VM with the serial console open and the
  operator's explicit go.

## Introduction

snitchd can enforce today, but only as a bounded hand-started run, and only through the test
script. This feature makes the daemon a service that is always on in monitor mode, and turns
deny-by-default into a trial: a deadline the operator sets, written to disk, that the daemon
follows and ends by itself, and that a reboot ends before anything enforces. Keeping enforce is
a separate, explicit step, and is itself a file an operator can delete from a console. A status
command shows what the daemon is doing. This is fail-safe 5 of the steering made real for
snitchd, in the shape that `snitch-trial` had for Little Snitch.

## Boundary Context

- **In scope**: the service unit and its start-up behaviour; the trial (start, follow, end at
  the deadline, end by command, survive a daemon restart, end at boot); keep and unkeep; the
  status command; the daemon's mode following files instead of a flag when run as a service;
  the enforce test extended to the trial flow; tests without root for the trial logic.
- **Out of scope**: deploying the unit to hosts (the VM repo's pyinfra flow); release
  packaging and the Nix flake; the unix socket API and the TUI (status is a command for now);
  changing the rules file format or the kernel program; a trial that enforces only for some
  programs (a trial is whole-host deny-by-default, as the kernel's mode is).
- **Adjacent expectations**: the kernel's fail-safes stay as they are (local network allowed,
  heartbeat fail-open, kill switch pinned across restarts). The bounded `-mode enforce
  -duration` run keeps existing for `scripts/enforce-test.sh`; the service never uses it.
  Learning mode never denies, so it and a trial exclude each other.

## Requirements

### Requirement 1: snitchd as a service
**Objective:** As the operator, I want snitchd to run from boot without my doing anything, so
that every connection is observed and rules are live, while nothing is denied by default.

#### Acceptance Criteria
1. The repository shall provide a service unit for snitchd that starts the daemon at boot as
   root with the default rules file and no mode flag, so that the daemon starts in monitor
   mode unless a kept enforce exists (Requirement 5).
2. When the service starts and the rules file is missing, the `snitchd` daemon shall start
   with no rules and report it, as it does today.
3. If the daemon exits with an error, the service shall restart it after a short delay, and
   while it is down every connection shall be allowed (the kernel fails open without a
   heartbeat).
4. The `snitchd` daemon shall log every mode change with its reason (trial started, deadline
   reached, ended by the operator, ended at boot, kept, unkept) to the service journal.
5. While the service runs, the kill switch set from a console shall keep allowing everything
   across daemon restarts until the operator clears it, as today.

### Requirement 2: Starting a trial
**Objective:** As the operator, I want to put the host into deny-by-default for a chosen time
with one command, so that I can see what my rules would block without committing to it.

#### Acceptance Criteria
1. When the operator runs the trial command with a duration, the `snitchd` control command
   shall record a deadline (now plus the duration) as a file on disk and the running daemon
   shall be in enforce mode within 5 seconds.
2. The trial command shall accept durations from 1 minute to 60 minutes and shall default to
   10 minutes when none is given; a longer enforce needs the keep step (Requirement 5).
3. If the kill switch is set, the trial command shall refuse to start a trial and shall say
   that enforce would have no effect until the kill switch is cleared.
4. If the daemon runs in learning mode, the trial command shall refuse to start a trial and
   shall say that learning never denies.
5. If a trial is already running, the trial command shall refuse a second one and shall show
   the remaining time, unless the operator asks to extend, in which case the deadline moves to
   now plus the new duration (still within the 60 minute bound).
6. If the daemon is not running, the trial command shall refuse to start a trial, because a
   deadline nobody follows would surprise the operator when the daemon comes up.
7. When a trial starts and the rules file has no rules, the trial command shall warn that
   every connection outside the local network will be denied, and shall still start the trial
   if the operator confirms.
8. The trial command shall print the deadline and how to end the trial early.

### Requirement 3: The daemon follows the deadline
**Objective:** As the operator, I want the trial to end by itself at the deadline, whatever
happens to my session, so that a wrong rule can never lock me out for longer than I chose.

#### Acceptance Criteria
1. While a trial deadline in the future is recorded and the daemon runs as a service, the
   `snitchd` daemon shall be in enforce mode.
2. When the deadline passes, the `snitchd` daemon shall switch to monitor mode within 5 seconds,
   shall remove the deadline, and shall log that the trial ended at its deadline.
3. If the daemon is restarted during a trial, the `snitchd` daemon shall come up in enforce
   mode and shall still end the trial at the recorded deadline.
4. If the operator removes the deadline file by hand (from any console), the `snitchd` daemon
   shall switch to monitor mode within 5 seconds and shall log that the trial was ended by the
   operator.
5. If the recorded deadline is unreadable or malformed, the `snitchd` daemon shall treat it as
   no trial, shall remove it, and shall log what it found.
6. While the daemon runs with the bounded `-mode enforce -duration` flags (the test script),
   the `snitchd` daemon shall ignore trial and keep files, so that the test's behaviour stays
   exactly as it is.

### Requirement 4: A reboot ends an open trial
**Objective:** As the operator, I want a reboot during a trial to come back in monitor mode,
so that the one recovery I always have never brings the denial back with it.

#### Acceptance Criteria
1. When the host boots and a trial deadline is recorded, the trial shall be ended (deadline
   removed, logged as ended at boot) before the daemon can enforce anything, whether the
   deadline is in the past or still in the future.
2. When the host boots and no kept enforce exists, the `snitchd` daemon shall start in monitor
   mode.
3. The boot-time end of a trial shall not depend on the network, on the rules file, or on the
   daemon having started successfully.

### Requirement 5: Keeping enforce, and taking it back
**Objective:** As the operator, I want to make enforce permanent only as a deliberate second
step after a trial has shown my rules work, and I want a way back that needs nothing but a
console.

#### Acceptance Criteria
1. While a trial is running, when the operator runs the keep command, the `snitchd` control
   command shall record the kept enforce as a file on disk, shall remove the trial deadline,
   and the daemon shall stay in enforce mode with no deadline.
2. If no trial is running, the keep command shall refuse and shall say that enforce can only be
   kept during a trial.
3. While a kept enforce is recorded, when the host boots, the `snitchd` daemon shall start in
   enforce mode (the one case where enforce survives a reboot).
4. When the operator runs the unkeep command, or removes the kept-enforce file by hand, the
   `snitchd` daemon shall switch to monitor mode within 5 seconds and shall log it.
5. The keep command shall print where the kept-enforce file is and the one command that
   removes it, so that the way back is known before enforce is kept.
6. While a kept enforce is recorded, the trial command shall refuse to start a trial and shall
   say that enforce is already kept.

### Requirement 6: Ending early
**Objective:** As the operator, I want one command that puts the host back into monitor mode
whatever state it is in, so that I never have to remember which file to delete.

#### Acceptance Criteria
1. When the operator runs the end command, the `snitchd` control command shall remove any trial
   deadline and any kept enforce, and the daemon shall be in monitor mode within 5 seconds.
2. When nothing is recorded, the end command shall report that the daemon is already in monitor
   mode and shall exit successfully.
3. The end command shall not touch the kill switch; `scripts/fail-open.sh` remains the console
   recovery for everything at once.

### Requirement 7: Status
**Objective:** As the operator, I want to see at a glance what the daemon is doing and what will
happen next, so that I can trust the state before and after a trial.

#### Acceptance Criteria
1. When the operator runs the status command, the `snitchd` control command shall show: whether
   the daemon is running, its mode, the trial deadline and remaining time if any, whether
   enforce is kept, the heartbeat age, whether the kill switch is set, and the rules summary
   (programs resolved, executables mapped, rules effective).
2. If the daemon is not running, the status command shall say so and shall still show the
   recorded trial and keep state and the kill switch.
3. The status command shall exit non-zero when the daemon is not running, so that scripts can
   check it.
4. The status command shall finish within one second.

### Requirement 8: Fail-safes preserved and proven
**Objective:** As the operator, I want the trial flow proven on the dev VM the same way the
first enforce test was, so that the service can be enabled with the lockout risk understood.

#### Acceptance Criteria
1. The enforce test script shall gain a trial phase, run only after the operator's go with the
   serial console open: start a trial of a few minutes, observe deny-by-default, restart the
   daemon and observe enforce resumes, end the trial by command and observe monitor, start
   another trial and observe it end at its deadline, run the boot-time end step by hand and
   observe monitor; keep and unkeep observed once; every step with the kill switch and the
   trap-protected reset of the first test.
2. While a trial runs, the local network, the kill switch and the heartbeat fail-open shall
   behave exactly as in the first enforce test.
3. The service unit shall not be enabled on the dev VM by this feature; enabling it is the
   operator's step through the VM repo, after the trial phase passed.
4. The trial logic (deadline recording and reading, mode decision from the files, bounds and
   refusals) shall be covered by tests that run without root.
