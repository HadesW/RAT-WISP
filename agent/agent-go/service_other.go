//go:build !windows

package main

import "errors"

func runAsService(func() error) error {
	return errors.New("--service is only supported on windows")
}
