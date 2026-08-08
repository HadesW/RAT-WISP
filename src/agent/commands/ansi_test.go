package commands

import (
	"strings"
	"testing"
)

func TestStripANSI(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{
			name: "plain text untouched",
			in:   "hello wisp",
			want: "hello wisp",
		},
		{
			name: "color codes removed",
			in:   "\x1b[1mroot\x1b[0m\x1b[38;5;42mPS>\x1b[0m",
			want: "rootPS>",
		},
		{
			name: "cursor modes removed",
			in:   "\x1b[?1hls\x1b[?1l",
			want: "ls",
		},
		{
			name: "osc title removed",
			in:   "\x1b]0;PS> root@kali: /tmp\x07ls",
			want: "ls",
		},
		{
			name: "osc with st terminator removed",
			in:   "x\x1b]8;;http://a\x1b\\link\x1b]8;;\x1b\\y",
			want: "xlinky",
		},
		{
			name: "charset designation removed",
			in:   "a\x1b(Bb",
			want: "ab",
		},
		{
			name: "pwsh prompt sample",
			in:   "PowerShell 7.6.2\n\n\x1b[1m┌──(\x1b[0m\x1b[1mroot㉿kali\x1b[0m\x1b[1m)-[\x1b[0m\x1b[1m/root\x1b[0m\x1b[1m]\x1b[0m\n\x1b[1m└─\x1b[0m\x1b[1mPS>\x1b[0m\x1b[1m]\x1b[0m",
			want: "PowerShell 7.6.2\n\n┌──(root㉿kali)-[/root]\n└─PS>]",
		},
	}

	for _, c := range cases {
		if got := stripANSI(c.in); got != c.want {
			t.Errorf("%s: stripANSI = %q, want %q", c.name, got, c.want)
		}
	}

	if strings.ContainsRune(stripANSI("\x1b[31mred\x1b[0m"), '\x1b') {
		t.Error("stripANSI must leave no ESC byte behind")
	}
}
