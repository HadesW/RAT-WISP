// Command e2e is a temporary end-to-end harness that starts an HTTP listener,
// builds a matching agent payload and prints its path, so the agent can be
// tested without the GUI.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/user/wisp/services"
)

func main() {
	protocolName := flag.String("protocol", "http", "listener protocol: tcp / http / https / kcp")
	port := flag.Int("port", 8080, "listener port")
	flag.Parse()

	// Use a throwaway data dir so we don't touch real data
	tmpDir, err := os.MkdirTemp("", "wisp-e2e")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}

	svc := services.NewServerService()
	svc.Initialize()

	row, err := svc.GetDB().CreateListener("e2e-"+*protocolName, *protocolName, "127.0.0.1", *port, *protocolName == "https", "")
	if err != nil {
		log.Fatalf("create listener: %v", err)
	}

	if err := svc.GetServer().StartListener(row.ID); err != nil {
		log.Fatalf("start listener: %v", err)
	}

	// Build a matching agent via the payload service
	agentOut := filepath.Join(tmpDir, "agent-e2e")
	if runtime.GOOS == "windows" {
		agentOut += ".exe"
	}
	ps := services.NewPayloadService(svc)
	built, err := ps.Generate(services.PayloadConfig{
		ListenerID: row.ID,
		TargetOS:   runtime.GOOS,
		TargetArch: runtime.GOARCH,
		Sleep:      1000,
		Jitter:     0,
		OutputPath: agentOut,
	})
	if err != nil {
		log.Fatalf("build agent payload: %v", err)
	}

	addr := fmt.Sprintf("%s://127.0.0.1:%d", *protocolName, *port)
	log.Printf("E2E listener up at %s", addr)
	log.Printf("AGENT_PATH=%s", built)
	log.Printf("Run: %s", built)

	// Run until killed
	time.Sleep(10 * time.Minute)
}
