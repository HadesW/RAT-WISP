#pragma once

// Minimal JSON writer/reader for the WISP++ envelope layer. No CRT, no
// exceptions; everything allocates through MemAllocLocal/MemFreeLocal.

#include <windows.h>

typedef struct WJVal WJVal;

typedef enum { WJ_NULL, WJ_BOOL, WJ_NUM, WJ_STR, WJ_ARR, WJ_OBJ } WJType;

struct WJVal
{
	WJType      type;
	BOOL        b;
	double      num;     // ints and floats (uint64 seq fits exactly)
	char*       str;     // WJ_STR (unescaped, NUL-terminated)
	WJVal**     items;   // WJ_ARR / WJ_OBJ values
	char**      keys;    // WJ_OBJ keys
	ULONG       count;
	ULONG       cap;
};

// Parse a JSON document; returns NULL on failure. Caller frees with WJFree.
WJVal* WJParse(const char* json, ULONG len);

// Serialize a value tree (compact). Caller frees the returned string.
char* WJSerialize(const WJVal* v);

void WJFree(WJVal* v);

// Builders (each returns a heap value or NULL).
WJVal* WJNewNull();
WJVal* WJNewBool(BOOL b);
WJVal* WJNewNum(double n);
WJVal* WJNewStr(const char* s);            // copies
WJVal* WJNewArr();
WJVal* WJNewObj();

// Mutators.
BOOL  WJArrPush(WJVal* arr, WJVal* item);
BOOL  WJObjPut(WJVal* obj, const char* key, WJVal* item);

// Accessors.
WJVal* WJObjGet(const WJVal* obj, const char* key); // NULL when absent
LONG64 WJNumAsI64(const WJVal* v, LONG64 def);

// Convenience: put key->string and key->number in one call.
BOOL WJObjPutStr(WJVal* obj, const char* key, const char* val);
BOOL WJObjPutNum(WJVal* obj, const char* key, double val);
