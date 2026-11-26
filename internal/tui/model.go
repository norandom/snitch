// Package tui is the pure UI state machine and screen renderer for the snitch TUI.
// It exchanges typed messages and effects with the terminal adapter and daemon client
// without touching a terminal library, sockets, files, or BPF maps.
//
// model.go: defines Options, Model, inbound messages, outbound effects, and New.
//
// Fail-safe implications: none on kernel egress. Pure state transitions over immutable
// Model values; every displayed or logged string uses clean.Safe.
package tui

import (
	"slices"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/table"
)

// Options configures a new Model at startup.
type Options struct {
	Conf      conf.Config
	Egress    bool
	Loc       *time.Location
	Socket    clean.Safe
	LogTail   []clean.Safe
	LogBroken bool
}

// Inbound messages besides client.Msg.
type (
	Key struct {
		Name   string
		Text   string
		Repeat bool
		At     time.Time
	}
	Paste     struct{ Text string }
	Resize    struct{ W, H int }
	Tick      struct{}
	LogFailed struct{ Err clean.Safe }
	Inspected struct {
		Path  string
		Loose bool
	}
)

// Outbound effects returned by Update.
type (
	Send struct {
		Token uint64
		Req   api.Request
	}
	Append  struct{ Line clean.Safe }
	Quit    struct{}
	Inspect struct{ Path string }
	Effect  any
)

type purposeKind int

const (
	purposeSnapshot purposeKind = iota
	purposeRules
	purposePrograms
	purposeBatch
	purposeTrial
	purposeKeep
	purposeEnd
	purposeUnkeep
)

type purpose struct {
	kind    purposeKind
	window  string
	batchID uint64
}

type batch struct {
	total    int
	done     int
	ok       int
	firstErr clean.Safe
	logLines []clean.Safe
	note     clean.Safe
}

type confirmKind int

const (
	confirmTrial confirmKind = iota
	confirmKeep
	confirmTrialForce
)

type confirmState struct {
	kind     confirmKind
	openedAt time.Time
	prompt   clean.Safe
}

type termSize struct {
	W int
	H int
}

// Model holds the entire TUI state as an immutable value; maps and slices are copied
// before modification so callers' prior Model values never change.
type Model struct {
	conf        conf.Config
	loc         *time.Location
	socket      clean.Safe
	logBroken   bool
	store       table.Store
	rules       table.Rules
	status      *api.Status
	state       *api.State
	up          bool
	foreign     bool
	stale       bool
	downReason  clean.Safe
	staleBeatAt time.Time
	killEvent   bool
	window      string
	resortIdx   int
	view        table.View
	rows        []table.Row
	dirty       bool
	cursor      table.RowID
	top         int
	graph       bool
	search      *string
	confirm     *confirmState
	armed       table.RowID
	nextToken   uint64
	pending     map[uint64]purpose
	batches     map[uint64]batch
	notice      clean.Safe
	log         []clean.Safe
	denied      map[string]time.Time
	inspected   map[string]bool
	rankedAt    time.Time
	builtAt     time.Time
	rebuilds    int
	snapAt      time.Time
	lastKeyAt   time.Time
	size        termSize
}

// New returns the initial TUI Model configured from o.
func New(o Options) Model {
	cfg := o.Conf
	if isZeroConfig(cfg) {
		cfg = conf.Default()
	}
	loc := o.Loc
	if loc == nil {
		loc = time.Local
	}
	win := cfg.Since
	if win == "" {
		win = "1h"
	}
	return Model{
		conf:      cfg,
		loc:       loc,
		socket:    o.Socket,
		logBroken: o.LogBroken,
		window:    win,
		graph:     o.Egress,
		log:       slices.Clone(o.LogTail),
		size:      termSize{W: minWidth, H: defaultHeight},
	}
}

func isZeroConfig(c conf.Config) bool {
	return c.Since == "" && len(c.Periods) == 0 && len(c.Protect) == 0 &&
		len(c.Resort) == 0 && c.Trial == 0
}

func (m Model) tooSmall() bool {
	return m.size.W < minWidth || m.size.H < minHeight
}
