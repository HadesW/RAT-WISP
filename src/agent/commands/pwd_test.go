package commands

import "testing"

func TestPwdCommand(t *testing.T) {
	d := NewDispatcher(nil, nil)
	d.cwd = `C:\Users\test`
	if out := d.execPwd(); out != `C:\Users\test` {
		t.Errorf("pwd = %q", out)
	}

	d.cwd = ""
	out := d.execPwd()
	if out == "" {
		t.Error("pwd should fall back to os.Getwd")
	}
}
