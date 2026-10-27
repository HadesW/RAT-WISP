//go:build windows

package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/svc"
)

const serviceName = "wisp-agent"

type agentService struct{ run func() error }

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- s.run() }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				log.Printf("agent: service stopped: %v", err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

func runAsService(run func() error) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !inService {
		return fmt.Errorf("--service must be started by the Service Control Manager (sc start)")
	}
	return svc.Run(serviceName, &agentService{run: run})
}
