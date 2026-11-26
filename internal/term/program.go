// Package term is the Bubble Tea v2 and Lip Gloss v2 adapter for the snitch TUI.
//
// No other package in this module may import charm.land/...; cmd/snitch/imports_test.go
// enforces this pin so untrusted strings from the daemon cannot reach the terminal renderer
// without passing through internal/clean and internal/tui first.
//
// Fail-safe implications: none on egress. This package speaks only to the user's terminal
// and never opens BPF maps, sockets or runtime files.
package term

import (
	"context"
	"fmt"
	"io"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/tui"
)

const (
	appWindowTitle = "snitch"
	tickInterval   = 500 * time.Millisecond
	maxInboxDrain  = 256
	defaultWidth   = 80
	defaultHeight  = 24
)

// Config wires the pure tui.Model to its runtime delegates and terminal streams.
type Config struct {
	Model  tui.Model
	In     <-chan any                // client messages and LogFailed
	Send   func(uint64, api.Request) // client.Send
	Log    func(clean.Safe) error    // logfile append
	Loose  func(path string) bool    // 13.5; run off the update path
	Now    func() time.Time
	Input  io.Reader
	Output io.Writer // os.Stdin, os.Stdout; buffers in tests
}

// Run returns a jobs.Job that runs the Bubble Tea program until Quit or ctx cancellation.
// It returns nil on Quit and ctx.Err() when ctx is cancelled after restoring the terminal.
func Run(c Config) jobs.Job {
	return func(ctx context.Context) error {
		runCtx, cancelRun := context.WithCancel(ctx)
		defer cancelRun()
		p := tea.NewProgram(newProgramModel(runCtx, c), programOptions(ctx, c)...)
		_, err := p.Run()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}

func programOptions(ctx context.Context, c Config) []tea.ProgramOption {
	opts := []tea.ProgramOption{
		tea.WithContext(ctx),
		tea.WithoutSignalHandler(),
		tea.WithInput(c.Input),
		tea.WithWindowSize(defaultWidth, defaultHeight),
	}
	if c.Output != nil {
		opts = append(opts, tea.WithOutput(c.Output))
	}
	return opts
}

type (
	tickMsg       struct{}
	inboxBatchMsg struct {
		msgs   []any
		closed bool
	}
	inboxClosedMsg struct{}
)

type programModel struct {
	ctx       context.Context
	cfg       Config
	model     tui.Model
	logFailed bool
}

func newProgramModel(ctx context.Context, cfg Config) programModel {
	return programModel{ctx: ctx, cfg: cfg, model: cfg.Model}
}

func (m programModel) now() time.Time {
	if m.cfg.Now != nil {
		return m.cfg.Now()
	}
	return time.Now()
}

func (m programModel) Init() tea.Cmd {
	if m.cfg.In == nil {
		return tickCmd()
	}
	return tea.Batch(tickCmd(), waitInboxCmd(m.ctx, m.cfg.In))
}

func (m programModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tickMsg:
		return m.step([]any{tui.Tick{}}, tickCmd())
	case inboxBatchMsg:
		var extra tea.Cmd
		if !v.closed && m.cfg.In != nil {
			extra = waitInboxCmd(m.ctx, m.cfg.In)
		}
		return m.step(v.msgs, extra)
	case inboxClosedMsg:
		return m, nil
	case tui.LogFailed, tui.Inspected:
		return m.step([]any{v}, nil)
	default:
		in, ok := translateMsg(msg, m.now())
		if !ok {
			return m, nil
		}
		return m.step([]any{in}, nil)
	}
}

func (m programModel) step(msgs []any, extra tea.Cmd) (tea.Model, tea.Cmd) {
	now := m.now()
	var cmds []tea.Cmd
	quitting := false
	for _, msg := range msgs {
		if _, isFail := msg.(tui.LogFailed); isFail {
			if m.logFailed {
				continue
			}
			m.logFailed = true
		}
		next, fx := tui.Update(m.model, msg, now)
		m.model = next
		fxCmds, quit := m.effectCmds(fx)
		cmds = append(cmds, fxCmds...)
		if quit {
			quitting = true
			break
		}
	}
	if quitting {
		return m, tea.Sequence(append(cmds, tea.Quit)...)
	}
	if extra != nil {
		cmds = append(cmds, extra)
	}
	return m, tea.Batch(cmds...)
}

func (m programModel) effectCmds(fx []tui.Effect) ([]tea.Cmd, bool) {
	var cmds []tea.Cmd
	quitting := false
	for _, e := range fx {
		switch eff := e.(type) {
		case tui.Quit:
			quitting = true
		case tui.Send:
			cmds = append(cmds, sendCmd(m.cfg.Send, eff))
		case tui.Append:
			cmds = append(cmds, appendCmd(m.cfg.Log, eff))
		case tui.Inspect:
			cmds = append(cmds, inspectCmd(m.cfg.Loose, eff))
		default:
			contract.Require(false, fmt.Sprintf("term: unknown effect %T", e))
		}
	}
	return cmds, quitting
}

func (m programModel) View() tea.View {
	scr := tui.Render(m.model, m.now())
	v := tea.NewView(renderScreen(scr))
	v.AltScreen = true
	v.MouseMode = tea.MouseModeNone
	v.Cursor = nil
	v.WindowTitle = appWindowTitle
	return v
}

func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(time.Time) tea.Msg { return tickMsg{} })
}

func waitInboxCmd(ctx context.Context, in <-chan any) tea.Cmd {
	return func() tea.Msg {
		select {
		case <-ctx.Done():
			return nil
		case first, ok := <-in:
			if !ok {
				return inboxClosedMsg{}
			}
			return drainInbox(in, first)
		}
	}
}

func drainInbox(in <-chan any, first any) inboxBatchMsg {
	msgs := []any{first}
	for len(msgs) < maxInboxDrain {
		select {
		case next, ok := <-in:
			if !ok {
				return inboxBatchMsg{msgs: msgs, closed: true}
			}
			msgs = append(msgs, next)
		default:
			return inboxBatchMsg{msgs: msgs}
		}
	}
	return inboxBatchMsg{msgs: msgs}
}

func sendCmd(fn func(uint64, api.Request), eff tui.Send) tea.Cmd {
	if fn == nil {
		return nil
	}
	return func() tea.Msg {
		fn(eff.Token, eff.Req)
		return nil
	}
}

func appendCmd(fn func(clean.Safe) error, eff tui.Append) tea.Cmd {
	if fn == nil {
		return nil
	}
	return func() tea.Msg {
		if err := fn(eff.Line); err != nil {
			return tui.LogFailed{Err: clean.Text(err.Error())}
		}
		return nil
	}
}

func inspectCmd(fn func(string) bool, eff tui.Inspect) tea.Cmd {
	if fn == nil {
		return nil
	}
	return func() tea.Msg {
		return tui.Inspected{Path: eff.Path, Loose: fn(eff.Path)}
	}
}
