//go:build !windows

package commands

// Token / post-exploitation commands are Windows-only; these stubs return a
// clean "unsupported" error so the agent still compiles everywhere.

func (d *Dispatcher) execTokenStealCmd(_ *Dispatcher, task *Task) *Result {
	return d.finish(task, "error: token manipulation is only supported on Windows", "failed")
}

func (d *Dispatcher) execTokenRevertCmd(_ *Dispatcher, task *Task) *Result {
	return d.finish(task, "error: token manipulation is only supported on Windows", "failed")
}

func (d *Dispatcher) execGetSystemCmd(_ *Dispatcher, task *Task) *Result {
	return d.finish(task, "error: getsystem is only supported on Windows", "failed")
}

func (d *Dispatcher) execHashdumpCmd(_ *Dispatcher, task *Task) *Result {
	return d.finish(task, "error: hashdump is only supported on Windows", "failed")
}

func (d *Dispatcher) execPersistCmd(_ *Dispatcher, task *Task) *Result {
	return d.finish(task, "error: registry persistence is only supported on Windows", "failed")
}

func (d *Dispatcher) execBrowserCredsCmd(_ *Dispatcher, task *Task) *Result {
	return d.finish(task, "error: browser credential harvesting is only supported on Windows", "failed")
}
