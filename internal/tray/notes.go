// notes.go: the texts of the state notices (7.1 to 7.6), one function per kind. Texts are
// plain; the notification adapter escapes them for body markup. A notice never has actions
// and closes on its own: 10 s, or 30 s and urgent for the attention states (kill switch,
// rules error, daemon gone), so those are not missed (7.8, design "Notices").
//
// Fail-safe implications: words only. No notice offers a button, so none can change the
// daemon. The texts claim only what the tray knows: an API without answer is not proof that
// the kernel side failed open, so the gone notice does not say so.
package tray

import (
	"time"

	"github.com/norandom/snitch/internal/client"
)

// The two lifetimes of a notice.
const (
	noticeTime    = 10 * time.Second
	attentionTime = 30 * time.Second
)

// notice is a plain note that closes after 10 s.
func notice(summary, body string) Note {
	return Note{Summary: "snitch: " + summary, Body: body, Timeout: noticeTime}
}

// attention is a notice for an attention state: urgent and 30 s.
func attention(summary, body string) Note {
	return Note{Summary: "snitch: " + summary, Body: body, Timeout: attentionTime, Urgent: true}
}

// noteTrial is a trial that started, its deadline in the tray's zone (7.1).
func noteTrial(deadline string, loc *time.Location) Note {
	at := deadline
	if t, err := time.Parse(time.RFC3339, deadline); err == nil {
		at = t.In(loc).Format("15:04 (2006-01-02)")
	}
	return notice("trial started", "Connections no rule allows are blocked until "+at+
		", then the daemon returns to monitor.")
}

// noteEnded is enforcement that ended, with the daemon's reason when one arrived (7.2).
func noteEnded(reason string) Note {
	if reason == "" {
		reason = "the daemon is in monitor mode"
	}
	return notice("enforcement ended", "Back to monitor: "+reason+".")
}

// noteKept is enforcement kept across reboots (7.3).
func noteKept() Note {
	return notice("enforce kept", "Enforcement stays on, also after a reboot, until it is unkept.")
}

// noteUnkept is kept enforcement given up, with the daemon's reason when one arrived (7.3);
// monitor says when the same change returned the daemon to monitor, like noteEnded.
func noteUnkept(reason string, monitor bool) Note {
	if reason == "" {
		reason = "enforcement is no longer kept"
	}
	if monitor {
		reason = "Back to monitor: " + reason
	}
	return notice("enforce unkept", reason+".")
}

// noteKill is the kill switch set or cleared (7.4).
func noteKill(set bool) Note {
	if set {
		return attention("kill switch set", "The kernel allows every connection until the kill switch is cleared.")
	}
	return notice("kill switch cleared", "The kernel decides by the rules again.")
}

// noteRulesError is a rules error with the daemon's text (7.5).
func noteRulesError(text string) Note {
	return attention("rules error", text)
}

// noteRulesOK is a rules error that cleared (7.5).
func noteRulesOK() Note {
	return notice("rules load again", "The rules error is gone.")
}

// noteGone is a daemon gone for 10 s, with the Down reason and when it went (7.6).
func noteGone(reason string, since time.Time, loc *time.Location) Note {
	if reason == "" {
		reason = client.NotRunning
	}
	return attention("daemon "+reason, "No answer from snitchd's API since "+
		since.In(loc).Format("15:04:05")+"; the tray retries on its own.")
}

// noteBack is the daemon back after a noticed loss (7.6).
func noteBack() Note {
	return notice("daemon back", "snitchd answers again.")
}
