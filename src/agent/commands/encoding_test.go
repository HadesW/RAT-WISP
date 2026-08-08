//go:build windows

package commands

import (
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestDecodeToUTF8(t *testing.T) {
	// GBK bytes (typical Windows cmd output) must decode to proper UTF-8
	enc := simplifiedchinese.GBK.NewEncoder()
	gbk, err := enc.Bytes([]byte("中文测试命令"))
	if err != nil {
		t.Fatalf("encode gbk: %v", err)
	}
	got := decodeToUTF8(gbk)
	if got != "中文测试命令" {
		t.Errorf("decodeToUTF8(GBK) = %q, want 中文测试命令", got)
	}

	// Already-UTF-8 bytes pass through unchanged
	if s := decodeToUTF8([]byte("正常UTF8文本")); s != "正常UTF8文本" {
		t.Errorf("UTF-8 passthrough = %q", s)
	}
}

// TestIshellChineseEcho verifies Chinese input AND output round-trips through
// the interactive cmd session (parameter execution carries Unicode correctly).
func TestIshellChineseEcho(t *testing.T) {
	d := NewDispatcher(nil, nil)

	out := d.execIshellOpen(jsonArgs(t, map[string]string{"shell": "cmd"}))
	if !strings.Contains(out, "interactive shell started") {
		t.Fatalf("open output = %q", out)
	}

	// Chinese command (input) whose output contains Chinese
	out = d.execIshellRun(jsonArgs(t, map[string]string{"input": "echo 中文测试命令"}))
	if !strings.Contains(out, "中文测试命令") {
		t.Errorf("ishell echo output = %q, want it to contain 中文测试命令", out)
	}

	d.execIshellClose()
}
