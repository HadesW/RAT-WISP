// plugin_sign: Ed25519 keypair + detached signatures for the plugin platform
// (plan §5.1). Signature message = manifest-bytes || module-bytes.
//
//	plugin_sign keygen -dir data/keys
//	plugin_sign sign -key data/keys/plugin.key -manifest m.json -module mod.wat
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		gk := flag.NewFlagSet("keygen", flag.ExitOnError)
		dir := gk.String("dir", "data/keys", "output dir")
		_ = gk.Parse(os.Args[2:])
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.MkdirAll(*dir, 0o700); err != nil {
			log.Fatal(err)
		}
		check(os.WriteFile(filepath.Join(*dir, "plugin.pub"), []byte(hex.EncodeToString(pub)), 0o600))
		check(os.WriteFile(filepath.Join(*dir, "plugin.key"), []byte(hex.EncodeToString(priv.Seed())), 0o600))
		fmt.Println("wrote", filepath.Join(*dir, "plugin.pub/.key"), "— 公钥 hex 配到 payload 的 plugin_pubkey")
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		key := fs.String("key", "", "plugin.key (hex seed)")
		man := fs.String("manifest", "", "manifest.json path")
		mod := fs.String("module", "", "module path")
		_ = fs.Parse(os.Args[2:])
		raw, err := os.ReadFile(*key)
		check(err)
		seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		check(err)
		if len(seed) != ed25519.SeedSize {
			log.Fatal("bad key size")
		}
		manifest, err := os.ReadFile(*man)
		check(err)
		module, err := os.ReadFile(*mod)
		check(err)
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append(append([]byte(nil), manifest...), module...))
		out := *mod + ".sig"
		check(os.WriteFile(out, []byte(hex.EncodeToString(sig)), 0o600))
		fmt.Println("sig ->", out, "| b64:", base64.StdEncoding.EncodeToString(sig))
	default:
		usage()
	}
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: plugin_sign keygen -dir DIR | sign -key K -manifest M -module F")
	os.Exit(2)
}
