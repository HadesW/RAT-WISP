// cfgslotprobe only reads its own configuration and exits; it never connects
// to a listener or executes agent commands.
package main

import (
	"fmt"
	"os"

	"wispp/protocol"
)

func main() {
	if protocol.SentinelSlot[0] != 0x57 {
		panic("missing sentinel") // retain the reserved data slot in the binary
	}
	path, err := os.Executable()
	if err != nil {
		panic(err)
	}
	image, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	cfg, ok, err := protocol.FindCfgSlot(image)
	if !ok || err != nil {
		panic(fmt.Sprintf("read config: %v, %v", ok, err))
	}
	fmt.Print(cfg.PSK)
}
