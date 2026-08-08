//go:build !windows

package commands

import "testing"

func TestParseDisplay(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		dnum     int
		hasError bool
	}{
		{":0", "", 0, false},
		{":1.0", "", 1, false},
		{"localhost:10", "localhost", 10, false},
		{"192.168.1.5:3", "192.168.1.5", 3, false},
		{"tcp/192.168.1.5:3", "192.168.1.5", 3, false},
		{"unix:0", "unix", 0, false},
		{":0.1", "", 0, false},
		{"no-colon", "", 0, true},
		{":abc", "", 0, true},
	}
	for _, c := range cases {
		host, dnum, err := parseDisplay(c.in)
		if c.hasError {
			if err == nil {
				t.Errorf("parseDisplay(%q): expected error, got host=%q dnum=%d", c.in, host, dnum)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDisplay(%q): unexpected error %v", c.in, err)
			continue
		}
		if host != c.host || dnum != c.dnum {
			t.Errorf("parseDisplay(%q) = (%q, %d), want (%q, %d)", c.in, host, dnum, c.host, c.dnum)
		}
	}
}

func TestVKToKeycode(t *testing.T) {
	cases := []struct {
		vk   int
		want int
	}{
		{0x41, 38}, // 'A'
		{90, 52},   // 'Z'
		{'0', 19},  // '0'
		{55, 16},   // '7'
		{32, 65},   // Space
		{13, 36},   // Enter
		{9, 23},    // Tab
		{8, 22},    // Backspace
		{27, 9},    // Escape
		{37, 113},  // Left
		{38, 111},  // Up
		{40, 116},  // Down
		{112, 67},  // F1
		{121, 76},  // F10
		{122, 95},  // F11
		{123, 96},  // F12
		{16, 50},   // Shift
		{17, 37},   // Ctrl
		{18, 64},   // Alt
		{20, 66},   // CapsLock
		{186, 47},  // ;
		{191, 61},  // /
		{219, 34},  // [
		{0, 0},     // unmapped
		{999, 0},   // out of range
	}
	for _, c := range cases {
		if got := vkToKeycode(c.vk); got != c.want {
			t.Errorf("vkToKeycode(%d) = %d, want %d", c.vk, got, c.want)
		}
	}
}
