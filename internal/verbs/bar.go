// bar.go formats the waybar JSON status line from the daemon's status and 1h snapshot.
//
// Fail-safe implications: none on kernel egress. Pure formatting; every daemon string
// passes clean.Text and stale/unreachable/kill/foreign states all surface as class "down".
package verbs

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

const (
	shieldDeny  = "\U000F0498" // solid shield (enforce)
	shieldAllow = "\U000F0499" // shield outline (monitor / down)
)

// Line is the status-bar JSON payload for waybar's custom module.
type Line struct {
	Text    string `json:"text"`
	Class   string `json:"class"`
	Tooltip string `json:"tooltip"`
}

// Bar builds a status-bar Line from st, the 1h snapshot entries, the current time, and
// any failure reason down from asking the daemon.
func Bar(st *api.Status, hour []api.Entry, now time.Time, down string) Line {
	cls := barClass(st, down)
	shield := shieldAllow
	if cls == "deny" {
		shield = shieldDeny
	}
	count := 0
	if down == "" && st != nil {
		count = deniedLastHour(hour, now)
	}
	text := shield
	if count > 0 {
		text += " " + strconv.Itoa(count)
	}
	return Line{
		Text:    text,
		Class:   cls,
		Tooltip: buildTooltip(st, count, now, down),
	}
}

func barClass(st *api.Status, down string) string {
	if down != "" || st == nil || st.Kill {
		return "down"
	}
	if st.Mode == "enforce" {
		return "deny"
	}
	return "allow"
}

func deniedLastHour(hour []api.Entry, now time.Time) int {
	n := 0
	for _, e := range hour {
		if e.LastBlocked == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, e.LastBlocked)
		if err != nil {
			continue
		}
		if d := now.Sub(t); d >= 0 && d <= time.Hour {
			n++
		}
	}
	return n
}

func buildTooltip(st *api.Status, count int, now time.Time, down string) string {
	if down != "" || st == nil {
		return downTooltip(count, down)
	}
	lines := make([]string, 0, 4)
	if st.Kill {
		lines = append(lines, cleanLine("snitch: down (kill switch set; kernel allows everything)"))
	}
	lines = append(lines, cleanLine(modeTooltip(st, now)))
	lines = append(lines, cleanLine(fmt.Sprintf("denied in the last hour: %d", count)))
	if st.RulesError != "" {
		lines = append(lines, cleanLine("rules error: "+st.RulesError))
	}
	return strings.Join(lines, "\n")
}

func downTooltip(count int, down string) string {
	reason := down
	if reason == "" {
		reason = "no status from daemon"
	}
	lines := []string{cleanLine("snitch: down (" + reason + ")")}
	if isNoAnswer(down) {
		lines = append(lines, cleanLine("daemon does not answer; kernel allows everything after 15 s"))
	}
	lines = append(lines, cleanLine(fmt.Sprintf("denied in the last hour: %d", count)))
	return strings.Join(lines, "\n")
}

func modeTooltip(st *api.Status, now time.Time) string {
	if st.Mode == "enforce" {
		if st.Kept {
			return "mode: enforce (deny by default, kept)"
		}
		if st.Trial != "" {
			return "mode: enforce (trial " + formatDeadline(st.Trial, now) + ")"
		}
		return "mode: enforce (deny by default)"
	}
	if st.Mode == "monitor" || st.Mode == "" {
		return "mode: monitor (allow by default)"
	}
	return "mode: " + st.Mode
}

func formatDeadline(raw string, now time.Time) string {
	dl, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "until " + raw
	}
	left := max(0, dl.Sub(now)).Round(time.Second)
	return fmt.Sprintf("until %s (%s left)", dl.In(now.Location()).Format("15:04"), left)
}

func isNoAnswer(reason string) bool {
	low := strings.ToLower(reason)
	return strings.Contains(low, "answer") ||
		strings.Contains(low, "deadline") ||
		strings.Contains(low, "timeout")
}

func cleanLine(s string) string {
	return string(clean.Text(s))
}
