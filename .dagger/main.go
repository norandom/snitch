// The snitch CI pipeline: one module, two doors (CI and the operator's machine).
//
// Every check, build and packaging step of the ci-debs feature is a function
// on the Ci facade and runs in a pinned container orchestrated by the Dagger
// engine. A pipeline run is therefore a container decision: it cannot leave
// the repository, the workstation or the runner half-built, and it mutates no
// host state beyond the engine's own caches. The GitHub workflows dispatch
// into this module, so a green CI run and a green local run mean the same
// thing (ci-debs design, requirements 1.1 and 1.2). This skeleton ships the
// facade and the pin registry only; the check, build, deb and smoke functions
// arrive with the tasks that own them.
package main

// Ci is the pipeline facade: the object whose methods are the `dagger call`
// targets. Keeping every function on one struct makes the listing printed by
// `dagger functions` from the repo root the pipeline's table of contents;
// pins.go beside this file is the single place where every image and tool
// version is decided.
type Ci struct{}
