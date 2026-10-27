package api

import (
	"net/http"
	"runtime"
	"time"
)

var apiStarted = time.Now()

// MetricsView is the operator-facing runtime summary (in-memory state + heap).
type MetricsView struct {
	UptimeSec  int64  `json:"uptime_sec"`
	Goroutines int    `json:"goroutines"`
	HeapAlloc  uint64 `json:"heap_alloc"`

	SessionsTotal   int `json:"sessions_total"`
	SessionsOnline  int `json:"sessions_online"`
	SessionsIdle    int `json:"sessions_idle"`
	SessionsOffline int `json:"sessions_offline"`

	TasksPending   int `json:"tasks_pending"`
	TasksSent      int `json:"tasks_sent"`
	TasksCompleted int `json:"tasks_completed"`
	TasksFailed    int `json:"tasks_failed"`

	JobsActive int `json:"jobs_active"`
	JobsDone   int `json:"jobs_done"`
	JobsFailed int `json:"jobs_failed"`

	ListenersTotal   int `json:"listeners_total"`
	ListenersRunning int `json:"listeners_running"`
	RCPOnline        int `json:"rcp_online"`
	StageActive      int `json:"stage_active"`
}

func (a *DebugAPI) metrics(w http.ResponseWriter, _ *http.Request) {
	m := MetricsView{
		UptimeSec:  int64(time.Since(apiStarted).Seconds()),
		Goroutines: runtime.NumGoroutine(),
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.HeapAlloc = ms.HeapAlloc

	if a.Hub != nil {
		sessions := a.Hub.Sessions("")
		m.SessionsTotal = len(sessions)
		for _, s := range sessions {
			switch s.Status {
			case "online":
				m.SessionsOnline++
			case "idle":
				m.SessionsIdle++
			default:
				m.SessionsOffline++
			}
		}
		for _, t := range a.Hub.Tasks("", "") {
			switch t.Status {
			case "pending":
				m.TasksPending++
			case "sent":
				m.TasksSent++
			case "completed":
				m.TasksCompleted++
			case "failed":
				m.TasksFailed++
			}
		}
	}
	if a.Files != nil {
		for _, j := range a.Files.Jobs("") {
			switch j.Status {
			case "done":
				m.JobsDone++
			case "failed":
				m.JobsFailed++
			default:
				m.JobsActive++
			}
		}
	}
	if a.Manager != nil {
		for _, l := range a.Manager.List() {
			m.ListenersTotal++
			if l.Running {
				m.ListenersRunning++
			}
		}
	}
	if a.RCP != nil {
		m.RCPOnline = a.RCP.OnlineCount()
	}
	if a.Payloads != nil && a.Payloads.Stage != nil {
		m.StageActive = a.Payloads.Stage.Active()
	}
	writeJSON(w, http.StatusOK, m)
}
