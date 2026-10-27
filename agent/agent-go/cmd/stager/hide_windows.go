//go:build windows

package main

import "golang.org/x/sys/windows"

func hideFile(path string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.SetFileAttributes(p, windows.FILE_ATTRIBUTE_HIDDEN)
}
