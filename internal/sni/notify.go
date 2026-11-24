// notify.go: the notification service of the session bus
// (org.freedesktop.Notifications): posting and retracting the tray's notes with an
// escaped body and actions as key and label pairs, and the presses and closes of the
// notes this process posted as messages for the loop (requirements 6.10, 8.6). The
// service's capabilities — that there is one, and whether it can show buttons — are
// a message at start and on every change of its owner, so the tray stays quiet on
// a desktop that cannot answer (8.6).
//
// Fail-safe implications: none on egress. Words and buttons only: no note and no
// capability message can reach the kernel state. Every call is bounded by the 2 s
// bus timeout because the loop runs Post synchronously — a failing or wedged
// service settles its question failed and never blocks the tray (2.1's note).
package sni

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/tray"
)

// The notification service's words on the wire, and the words of the tray's
// notes: the app name, the pixmap-free app icon as a theme name, and the desktop
// entry the notes are tied to (research.md, "Notifications"; the design's Notify).
const (
	notifyName      = "org.freedesktop.Notifications"
	notifyPath      = dbus.ObjectPath("/org/freedesktop/Notifications")
	notifyIface     = "org.freedesktop.Notifications"
	notifyInvoked   = notifyIface + ".ActionInvoked"
	notifyClosedSig = notifyIface + ".NotificationClosed"
	notifyApp       = "snitch"
	notifyIcon      = "security-medium"
	notifyEntry     = "snitch-tray"
	urgencyNormal   = byte(1) // the spec's 0..2 scale; a note is a normal one
	urgencyCritical = byte(2) // an urgent note is critical, so it is not missed
)

// notifier is the tray's side of the notification service: post and retract for the
// loop's Post and Retract delegates, the capabilities and the presses and closes as
// messages through the sink. The posted ids are the ones the signals are filtered
// by — another application's note is silence.
type notifier struct {
	bus     *Bus
	sink    func(any)
	log     func(string)
	owners  <-chan string
	signals <-chan *dbus.Signal
	posted  sync.Map // the note ids this process's Notify calls were answered with
}

// notify subscribes to the service's signals and its owner changes; the
// capabilities and the presses and closes flow with the watch that the adapter's
// job runs.
func (b *Bus) notify(sink func(any), log func(string)) (*notifier, error) {
	contract.Require(b != nil && b.conn != nil, "sni: notifications on a nil bus")
	contract.Require(!b.closed.Load(), "sni: notifications on a closed bus")
	contract.Require(sink != nil, "sni: notifications need a sink for the messages")
	contract.Require(log != nil, "sni: notifications need a log delegate")
	in := make(chan *dbus.Signal, 16)
	b.conn.Signal(in)
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	err := b.conn.AddMatchSignalContext(ctx, dbus.WithMatchInterface(notifyIface))
	if err != nil {
		b.conn.RemoveSignal(in)
		return nil, fmt.Errorf("watch notification signals: %w", err)
	}
	owners, err := b.watchOwner(notifyName)
	if err != nil {
		b.conn.RemoveSignal(in)
		return nil, err
	}
	return &notifier{bus: b, sink: sink, log: log, owners: owners, signals: in}, nil
}

// post makes one note a notification and answers the id the service gave it —
// the loop keeps that id and retracts by it. The body is escaped, because the
// services parse body markup, and the note's answers are the actions, as key and
// label pairs; the id lands in our set, which is the only one whose signals
// become messages.
func (n *notifier) post(note tray.Note) (uint32, error) {
	var id uint32
	err := n.call("Notify", notifyApp, uint32(0), notifyIcon, note.Summary,
		escapeBody(note.Body), actionPairs(note.Actions), notifyHints(note),
		noteTimeout(note)).Store(&id)
	if err != nil {
		return 0, fmt.Errorf("post a note: %w", err)
	}
	// The tray's model means id 0 as "no note open", so a service answering with
	// 0 is refused: the loop settles the question failed instead of confusing it.
	if id == 0 {
		return 0, fmt.Errorf("post a note: the service answered with id 0")
	}
	n.posted.Store(id, true)
	return id, nil
}

// retract closes the note: its buttons die with it. A failing call is spoken for
// the log, not an error for the loop — the loop is done with the note already.
func (n *notifier) retract(id uint32) {
	if err := n.call("CloseNotification", id).Err; err != nil {
		n.log(fmt.Sprintf("close the note %d: %v", id, err))
	}
}

// call asks the notification service, bounded like every call on the bus.
func (n *notifier) call(method string, args ...any) *dbus.Call {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return n.bus.conn.Object(notifyName, notifyPath).
		CallWithContext(ctx, notifyIface+"."+method, 0, args...)
}

// actionPairs flattens the note's answers into the service's alternating key and
// label list. The default key never reaches the wire — that key is the body
// click, and a question's body click is not an answer (6.10); an empty key is no
// key at all.
func actionPairs(actions []tray.Action) []string {
	pairs := make([]string, 0, 2*len(actions))
	for _, a := range actions {
		if a.Key == "" || a.Key == "default" {
			continue
		}
		pairs = append(pairs, a.Key, a.Label)
	}
	return pairs
}

// notifyHints carries the design's three: urgency by the spec's scale, transient
// true so an expired note leaves no history behind — its buttons must not
// outlive its question — and the desktop entry of the tray.
func notifyHints(note tray.Note) map[string]dbus.Variant {
	urgency := urgencyNormal
	if note.Urgent {
		urgency = urgencyCritical
	}
	return map[string]dbus.Variant{
		"urgency":       dbus.MakeVariant(urgency),
		"transient":     dbus.MakeVariant(true),
		"desktop-entry": dbus.MakeVariant(notifyEntry),
	}
}

// noteTimeout is the note's lifetime in the service's milliseconds; a note
// without one leaves the expiry to the service.
func noteTimeout(note tray.Note) int32 {
	if note.Timeout <= 0 {
		return -1
	}
	return int32(note.Timeout / time.Millisecond)
}

// escapeBody escapes the markup words of the spec's body markup: an ampersand, a
// less and a greater in a path or a name must stand escaped, because the body is
// parsed even where it looks like plain text.
func escapeBody(body string) string {
	if !strings.ContainsAny(body, "&<>") {
		return body
	}
	var out strings.Builder
	for _, r := range body {
		switch r {
		case '&':
			out.WriteString("&amp;")
		case '<':
			out.WriteString("&lt;")
		case '>':
			out.WriteString("&gt;")
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// watch is the notification side of the adapter's job: the capabilities at start
// and on every change of the service's owner, the presses and closes of our
// notes as messages, and ErrBusLost when the bus is gone — the tray's end.
func (n *notifier) watch(ctx context.Context) error {
	n.capabilities()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case owner, ok := <-n.owners:
			if !ok {
				return ErrBusLost
			}
			n.ownerCaps(owner)
		case sig, ok := <-n.signals:
			if !ok {
				return ErrBusLost
			}
			n.signal(sig)
		}
	}
}

// capabilities says what the service can do at start: an absent service is not
// available, and one whose state cannot be read is spoken and treated the same —
// the fail-safe side of 8.6 is to ask nothing.
func (n *notifier) capabilities() {
	owner, owned, err := n.bus.owner(notifyName)
	if err != nil {
		n.log("the notification service's state is unknown: " + err.Error())
		n.sink(tray.Capabilities{})
		return
	}
	if !owned {
		n.sink(tray.Capabilities{})
		return
	}
	n.ownerCaps(owner)
}

// ownerCaps turns the service's answer into the loop's capabilities message:
// available is a service that answers, actions is whether it offers buttons
// (8.6). Our posted ids die with the owner they belong to: a new owner's ids
// start over, so an old id of ours would be a foreign note now.
func (n *notifier) ownerCaps(owner string) {
	n.posted.Clear()
	if owner == "" {
		n.sink(tray.Capabilities{})
		return
	}
	var caps []string
	if err := n.call("GetCapabilities").Store(&caps); err != nil {
		n.log("the notification service does not answer: " + err.Error())
		n.sink(tray.Capabilities{})
		return
	}
	n.sink(tray.Capabilities{Available: true, Actions: slices.Contains(caps, "actions")})
}

// signal turns one service signal into a message, and only for a note this
// process posted — every other id is another application's business (6.10). A
// note is forgotten once the service closed it, so the set of ours stays small.
func (n *notifier) signal(s *dbus.Signal) {
	if len(s.Body) < 2 {
		return
	}
	id, _ := s.Body[0].(uint32)
	switch s.Name {
	case notifyInvoked:
		if key, ok := s.Body[1].(string); ok {
			if _, mine := n.posted.Load(id); mine {
				n.sink(tray.Pressed{NoteID: id, Action: key})
			}
		}
	case notifyClosedSig:
		if _, mine := n.posted.LoadAndDelete(id); mine {
			n.sink(tray.Closed{NoteID: id})
		}
	}
}
