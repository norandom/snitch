// Package tray is the tray's whole behaviour as a pure update over one model value, plus the
// loop that runs it. Adapters on both sides (internal/client for the daemon, internal/sni for
// the session bus) turn traffic into messages and run the effects; this package knows neither
// sockets nor D-Bus.
//
// model.go: the model value, the options, the seven states, and every message and effect type
// the loop exchanges with its adapters (design "Components and Interfaces > Core > tray").
//
// Fail-safe implications: none on the kernel side. The tray displays the daemon's facts and
// its only write is rule.add on an explicit answer (6.12, 8.1); no type here can express a
// trial verb, the kill switch or a mode change, so the menu cannot offer one (3.5).
package tray

import (
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
)

// State is what the icon shows; the order of the constants is the order of 2.2, first that
// holds wins.
type State int

const (
	Gone State = iota
	Blind
	Kill
	RulesError
	Kept
	Trial
	Monitor
)

// String is the state in words, as the title, the tooltip and the menu header say it.
func (s State) String() string {
	switch s {
	case Gone:
		return "daemon not running"
	case Blind:
		return "kernel hook inactive"
	case Kill:
		return "kill switch set"
	case RulesError:
		return "rules error"
	case Kept:
		return "enforce kept"
	case Trial:
		return "enforce trial"
	case Monitor:
		return "monitor"
	}
	return "unknown state"
}

// Attention is true for the states the desktop must not hide among inactive items (2.3).
func (s State) Attention() bool {
	return s == Gone || s == Blind || s == Kill || s == RulesError
}

// Options are the tray's start settings.
type Options struct {
	Scope  ask.Scope      // -ask all | enforce
	Writer bool           // client.Role at start: the user may answer questions
	Loc    *time.Location // the zone times are shown in; nil is time.Local (tests pass a fixed one)
}

// Model is the tray's state, a value: Update (later tasks) returns a new one. Fields that
// point to data (facts, notices, pending) are never written through: a change copies the map
// or replaces the pointer, so an earlier model value never changes under its holder.
//
// gone and facts (for 3.2): known() shows facts only while gone is false, so gone must stay
// true after Up until the first Facts of that session has replaced facts; clearing it on Up
// would show the last session's stale facts (3.3). The facts of the last session stay in
// the model while gone, as the baseline the notices of a reconnect are compared with.
type Model struct {
	opts        Options
	loc         *time.Location
	facts       *api.Status        // the last status; nil until the daemon has sent one
	gone        bool               // no current status: facts are stale and never shown
	down        string             // the Down reason while gone (client.NotRunning or NotAnswering)
	goneSince   time.Time          // when the Down came: the notice waits until 10 s have passed (7.6)
	goneNoticed bool               // the gone notice was posted, so the next Up gives notice too
	lastReason  string             // the last state line's reason, for "enforcement ended" (7.2)
	paused      bool               // questions paused from the menu (5.10)
	canNotify   bool               // a notification service is present (8.6)
	canAct      bool               // and it shows action buttons (8.6)
	writer      bool               // this user may answer: operator (3.1, 6.9)
	queue       ask.Queue          // the waiting list and the open question; the zero value is empty
	askToken    uint64             // the token of the open question's post until posted/postFailed, 0 when none
	openActs    bool               // the open question's note was posted with Allow and Block (6.5, 6.9)
	openNote    uint32             // the posted note of the open question, 0 when none (6.11)
	openSince   time.Time          // when that note was posted: the tray's own 60 s timeout (6.10)
	notices     map[uint32]bool    // ids of posted notices until their Closed, retracted on quit (1.4)
	posting     map[uint64]bool    // tokens of notices posted but not yet posted/postFailed (questions' tokens are 3.3's)
	pending     map[uint64]ask.Key // token of a rule.add in flight -> its question's key (6.8)
	nextToken   uint64             // the token of the next post or send; 0 is never used
}

// NewModel is the model at start: no facts yet and gone, so the view is the gone state until
// the first Facts (3.3); no notification service until one is reported (8.6); nothing open,
// waiting, posted or in flight.
func NewModel(o Options) Model {
	loc := o.Loc
	if loc == nil {
		loc = time.Local
	}
	return Model{opts: o, loc: loc, writer: o.Writer, gone: true}
}

// Messages the loop feeds to Update besides the client's (client.Up, Down, Facts, StateLine,
// EventLine, Answered).
type (
	Tick         struct{}                          // the one second tick
	Stop         struct{}                          // a termination signal
	Capabilities struct{ Available, Actions bool } // the notification service at start and on change
	posted       struct {                          // a post effect succeeded
		Token  uint64
		NoteID uint32
	}
	postFailed struct{ Token uint64 }
	Pressed    struct { // an action button of a note: "allow" or "block"
		NoteID uint32
		Action string
	}
	Closed    struct{ NoteID uint32 } // dismissed, expired or closed by the server
	MenuClick struct{ Row RowID }
)

// Effects Update asks the loop to run.
type (
	show struct{ View View }
	post struct {
		Token uint64
		Note  Note
	}
	retract struct{ NoteID uint32 }
	send    struct {
		Token uint64
		Req   api.Request
	}
	quit struct{}
)

// View is everything the desktop shows, rendered from one model at one time, so the icon and
// the menu never disagree (3.6).
type View struct {
	State     State
	Attention bool
	Title     string
	Tooltip   string
	Menu      []Row
}

// RowID names a menu row; the set is closed (3.5). Zero is not a row: dbusmenu uses id 0
// for its root.
type RowID int

const (
	RowHeader RowID = iota + 1
	RowMode
	RowTrial
	RowKept
	RowKill
	RowLearning
	RowCounts
	RowRulesFile
	RowOverlay
	RowDNS
	RowDaemon
	RowRole
	RowRulesError
	RowHook
	RowNoAnswer
	RowSeparator
	RowPause
	RowQuit
)

// Row is one entry of the flat menu. Labels are plain text; the adapter escapes them.
type Row struct {
	ID        RowID
	Label     string
	Separator bool
	Enabled   bool
	Check     bool // a checkmark row
	Checked   bool
}

// Note is one notification: a question, an outcome or a notice.
type Note struct {
	Summary, Body string   // plain text; the adapter escapes for body-markup
	Actions       []Action // none, or allow and block
	Timeout       time.Duration
	Urgent        bool
}

// Action is one button of a note.
type Action struct{ Key, Label string }

// Effects are the loop's delegates: the bus side (Show, Post, Retract), the daemon side
// (Send) and the clock.
type Effects struct {
	Show    func(View)
	Post    func(Note) (uint32, error)
	Retract func(uint32)
	Send    func(uint64, api.Request)
	Now     func() time.Time
}
