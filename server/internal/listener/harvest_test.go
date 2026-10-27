package listener

import (
	"testing"

	"wispp/protocol"
)

func TestAutoHarvestOnFirstRegister(t *testing.T) {
	l := newCore(t)
	l.Harvest = DefaultHarvest()
	hl := &HTTPListener{Core: l, Profile: protocol.DefaultProfile()}
	ts := newServer(hl)
	defer ts.Close()

	send := mkSender(t, ts)
	if _, ack := registerRoundTrip(t, send, l, "hh001122", l.PSK); !ack.OK {
		t.Fatal("register rejected")
	}
	tasks := l.Hub.Tasks("hh001122", "")
	if len(tasks) != len(DefaultHarvest()) {
		t.Fatalf("harvest queued %d, want %d", len(tasks), len(DefaultHarvest()))
	}
	want := []uint32{protocol.CmdSysinfo, protocol.CmdPwd, protocol.CmdShell}
	for _, cmd := range want {
		if tasksByCmd(l, cmd) == 0 {
			t.Fatalf("missing harvest task cmd=%d", cmd)
		}
	}
	// re-registration must NOT re-harvest
	if _, ack := registerRoundTrip(t, send, l, "hh001122", l.PSK); !ack.OK {
		t.Fatal("re-register rejected")
	}
	if got := len(l.Hub.Tasks("hh001122", "")); got != len(DefaultHarvest()) {
		t.Fatalf("re-register re-harvested: %d tasks", got)
	}
}

func tasksByCmd(l Core, cmd uint32) int {
	n := 0
	for _, r := range l.Hub.Tasks("", "") {
		if r.Task.Cmd == cmd {
			n++
		}
	}
	return n
}
