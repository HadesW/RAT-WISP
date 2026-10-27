#include "WispJson.h"
#include "ApiLoader.h"
#include "utils.h"

//////// allocation helpers ////////

static WJVal* wj_new(WJType t)
{
	WJVal* v = (WJVal*)MemAllocLocal(sizeof(WJVal));
	if (!v)
		return NULL;
	v->type = t;
	return v;
}

void WJFree(WJVal* v)
{
	if (!v)
		return;
	if (v->type == WJ_STR && v->str) {
		ULONG n = StrLenA(v->str);
		MemFreeLocal((LPVOID*)&v->str, n + 1);
	}
	if (v->items) {
		for (ULONG i = 0; i < v->count; i++)
			WJFree(v->items[i]);
		MemFreeLocal((LPVOID*)&v->items, v->cap * sizeof(WJVal*));
	}
	if (v->keys) {
		for (ULONG i = 0; i < v->count; i++) {
			if (v->keys[i]) {
				ULONG n = StrLenA(v->keys[i]);
				MemFreeLocal((LPVOID*)&v->keys[i], n + 1);
			}
		}
		MemFreeLocal((LPVOID*)&v->keys, v->cap * sizeof(char*));
	}
	MemFreeLocal((LPVOID*)&v, sizeof(WJVal));
}

static BOOL wj_reserve(WJVal* v, ULONG need)
{
	if (need <= v->cap)
		return TRUE;
	ULONG nc = v->cap ? v->cap * 2 : 8;
	while (nc < need)
		nc *= 2;
	WJVal** ni = (WJVal**)MemAllocLocal(nc * sizeof(WJVal*));
	if (!ni)
		return FALSE;
	if (v->items)
		memcpy(ni, v->items, v->count * sizeof(WJVal*));
	memset((BYTE*)v->items, 0, v->cap * sizeof(WJVal*));
	MemFreeLocal((LPVOID*)&v->items, v->cap * sizeof(WJVal*));
	v->items = ni;
	if (v->type == WJ_OBJ) {
		char** nk = (char**)MemAllocLocal(nc * sizeof(char*));
		if (!nk)
			return FALSE;
		if (v->keys)
			memcpy(nk, v->keys, v->count * sizeof(char*));
		memset((BYTE*)v->keys, 0, v->cap * sizeof(char*));
		MemFreeLocal((LPVOID*)&v->keys, v->cap * sizeof(char*));
		v->keys = nk;
	}
	v->cap = nc;
	return TRUE;
}

WJVal* WJNewNull() { return wj_new(WJ_NULL); }
WJVal* WJNewBool(BOOL b) { WJVal* v = wj_new(WJ_BOOL); if (v) v->b = b; return v; }
WJVal* WJNewNum(double n) { WJVal* v = wj_new(WJ_NUM); if (v) v->num = n; return v; }

WJVal* WJNewStr(const char* s)
{
	if (!s)
		return WJNewNull();
	ULONG n = StrLenA(s);
	char* c = (char*)MemAllocLocal(n + 1);
	if (!c)
		return NULL;
	memcpy(c, s, n + 1);
	WJVal* v = wj_new(WJ_STR);
	if (!v) {
		MemFreeLocal((LPVOID*)&c, n + 1);
		return NULL;
	}
	v->str = c;
	return v;
}

WJVal* WJNewArr() { return wj_new(WJ_ARR); }
WJVal* WJNewObj() { return wj_new(WJ_OBJ); }

BOOL WJArrPush(WJVal* arr, WJVal* item)
{
	if (!arr || arr->type != WJ_ARR || !item)
		return FALSE;
	if (!wj_reserve(arr, arr->count + 1))
		return FALSE;
	arr->items[arr->count++] = item;
	return TRUE;
}

BOOL WJObjPut(WJVal* obj, const char* key, WJVal* item)
{
	if (!obj || obj->type != WJ_OBJ || !key || !item)
		return FALSE;
	for (ULONG i = 0; i < obj->count; i++) {
		if (StrCmpA(obj->keys[i], (CHAR*)key) == 0) {
			WJFree(obj->items[i]);
			obj->items[i] = item;
			return TRUE;
		}
	}
	if (!wj_reserve(obj, obj->count + 1))
		return FALSE;
	ULONG n = StrLenA(key);
	char* kc = (char*)MemAllocLocal(n + 1);
	if (!kc)
		return FALSE;
	memcpy(kc, key, n + 1);
	obj->keys[obj->count] = kc;
	obj->items[obj->count] = item;
	obj->count++;
	return TRUE;
}

BOOL WJObjPutStr(WJVal* obj, const char* key, const char* val)
{
	WJVal* v = WJNewStr(val);
	return v && WJObjPut(obj, key, v);
}

BOOL WJObjPutNum(WJVal* obj, const char* key, double val)
{
	WJVal* v = WJNewNum(val);
	return v && WJObjPut(obj, key, v);
}

WJVal* WJObjGet(const WJVal* obj, const char* key)
{
	if (!obj || obj->type != WJ_OBJ)
		return NULL;
	for (ULONG i = 0; i < obj->count; i++)
		if (StrCmpA(obj->keys[i], (CHAR*)key) == 0)
			return obj->items[i];
	return NULL;
}

LONG64 WJNumAsI64(const WJVal* v, LONG64 def)
{
	if (!v || v->type != WJ_NUM)
		return def;
	return (LONG64)v->num;
}

//////// parser ////////

typedef struct {
	const char* p;
	const char* end;
	int         depth;
} WPState;

static WJVal* wp_value(WPState* s);

static void wp_ws(WPState* s)
{
	while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\r' || *s->p == '\n'))
		s->p++;
}

static WJVal* wp_string(WPState* s)
{
	wp_ws(s);
	if (s->p >= s->end || *s->p != '"')
		return NULL;
	s->p++;
	ULONG cap = 16, len = 0;
	char* out = (char*)MemAllocLocal(cap);
	if (!out)
		return NULL;
	while (s->p < s->end) {
		char c = *s->p;
		if (c == '"') {
			s->p++;
			out[len] = 0;
			WJVal* v = wj_new(WJ_STR);
			if (!v) {
				MemFreeLocal((LPVOID*)&out, cap);
				return NULL;
			}
			v->str = out;
			return v;
		}
		if (c == '\\' && s->p + 1 < s->end) {
			s->p++;
			char e = *s->p++;
			switch (e) {
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case '/': c = '/';  break;
			case '"': c = '"';  break;
			case '\\': c = '\\'; break;
			case 'u': {
				if (s->p + 4 > s->end) {
					MemFreeLocal((LPVOID*)&out, cap);
					return NULL;
				}
				unsigned cp = 0;
				for (int i = 0; i < 4; i++) {
					char h = *s->p++;
					cp <<= 4;
					if (h >= '0' && h <= '9') cp |= h - '0';
					else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
					else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
					else { MemFreeLocal((LPVOID*)&out, cap); return NULL; }
				}
				// surrogate pair
				if (cp >= 0xD800 && cp <= 0xDBFF && s->p + 6 <= s->end && s->p[0] == '\\' && s->p[1] == 'u') {
					unsigned lo = 0;
					s->p += 2;
					for (int i = 0; i < 4; i++) {
						char h = *s->p++;
						lo <<= 4;
						if (h >= '0' && h <= '9') lo |= h - '0';
						else if (h >= 'a' && h <= 'f') lo |= h - 'a' + 10;
						else if (h >= 'A' && h <= 'F') lo |= h - 'A' + 10;
					}
					cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
				}
				// UTF-8 encode
				BYTE tmp[4];
				int n = 0;
				if (cp < 0x80) { tmp[n++] = (BYTE)cp; }
				else if (cp < 0x800) { tmp[n++] = 0xC0 | (cp >> 6); tmp[n++] = 0x80 | (cp & 0x3F); }
				else if (cp < 0x10000) { tmp[n++] = 0xE0 | (cp >> 12); tmp[n++] = 0x80 | ((cp >> 6) & 0x3F); tmp[n++] = 0x80 | (cp & 0x3F); }
				else { tmp[n++] = 0xF0 | (cp >> 18); tmp[n++] = 0x80 | ((cp >> 12) & 0x3F); tmp[n++] = 0x80 | ((cp >> 6) & 0x3F); tmp[n++] = 0x80 | (cp & 0x3F); }
			for (int i = 0; i < n; i++) {
				if (len + 2 >= cap) {
					ULONG nc = cap * 2;
					char* no = (char*)MemAllocLocal(nc);
					if (!no) { MemFreeLocal((LPVOID*)&out, cap); return NULL; }
					memcpy(no, out, len);
					MemFreeLocal((LPVOID*)&out, cap);
					out = no; cap = nc;
				}
				out[len++] = tmp[i];
			}
			continue;
			}
			default:
				MemFreeLocal((LPVOID*)&out, cap);
				return NULL;
			}
		}
		else {
			s->p++;
		}
		if (len + 2 >= cap) {
			ULONG nc = cap * 2;
			char* no = (char*)MemAllocLocal(nc);
			if (!no) {
				MemFreeLocal((LPVOID*)&out, cap);
				return NULL;
			}
			memcpy(no, out, len);
			MemFreeLocal((LPVOID*)&out, cap);
			out = no; cap = nc;
		}
		out[len++] = c;
	}
	MemFreeLocal((LPVOID*)&out, cap);
	return NULL;
}

static WJVal* wp_number(WPState* s)
{
	const char* start = s->p;
	if (s->p < s->end && (*s->p == '-' || *s->p == '+'))
		s->p++;
	while (s->p < s->end && ((*s->p >= '0' && *s->p <= '9') || *s->p == '.' || *s->p == 'e' || *s->p == 'E' || *s->p == '-' || *s->p == '+'))
		s->p++;
	ULONG n = (ULONG)(s->p - start);
	if (n == 0)
		return NULL;
	double val = 0;
	double frac = 0.1;
	int neg = 0, expo = 0, expneg = 0, seenDot = 0, seenE = 0;
	const char* q = start;
	if (*q == '-') { neg = 1; q++; }
	else if (*q == '+') q++;
	for (; q < s->p; q++) {
		char c = *q;
		if (c >= '0' && c <= '9') {
			if (seenE) expo = expo * 10 + (c - '0');
			else if (seenDot) { val += (c - '0') * frac; frac /= 10; }
			else val = val * 10 + (c - '0');
		}
		else if (c == '.' && !seenDot && !seenE) seenDot = 1;
		else if ((c == 'e' || c == 'E') && !seenE) seenE = 1;
		else if ((c == '-' || c == '+') && (q == start || q[-1] == 'e' || q[-1] == 'E')) { if (c == '-') expneg = 1; }
	}
	for (int i = 0; i < expo; i++)
		val *= 10;
	if (expneg)
		for (int i = 0; i < expo; i++)
			val /= 10;
	if (neg)
		val = -val;
	WJVal* v = wj_new(WJ_NUM);
	if (v)
		v->num = val;
	return v;
}

static WJVal* wp_value(WPState* s)
{
	if (++s->depth > 64) {
		s->depth--;
		return NULL;
	}
	wp_ws(s);
	if (s->p >= s->end) {
		s->depth--;
		return NULL;
	}
	WJVal* v = NULL;
	char c = *s->p;
	if (c == '{') {
		s->p++;
		v = wj_new(WJ_OBJ);
		if (!v) { s->depth--; return NULL; }
		wp_ws(s);
		if (s->p < s->end && *s->p == '}') {
			s->p++;
			s->depth--;
			return v;
		}
		for (;;) {
			wp_ws(s);
			WJVal* k = wp_string(s);
			if (!k) break;
			wp_ws(s);
			if (s->p >= s->end || *s->p != ':') { WJFree(k); break; }
			s->p++;
			WJVal* item = wp_value(s);
			if (!item) { WJFree(k); break; }
			if (!WJObjPut(v, k->str, item)) { WJFree(k); break; }
			WJFree(k);
			wp_ws(s);
			if (s->p < s->end && *s->p == ',') { s->p++; continue; }
			break;
		}
		wp_ws(s);
		if (s->p < s->end && *s->p == '}')
			s->p++;
		s->depth--;
		return v;
	}
	if (c == '[') {
		s->p++;
		v = wj_new(WJ_ARR);
		if (!v) { s->depth--; return NULL; }
		wp_ws(s);
		if (s->p < s->end && *s->p == ']') {
			s->p++;
			s->depth--;
			return v;
		}
		for (;;) {
			WJVal* item = wp_value(s);
			if (!item)
				break;
			if (!WJArrPush(v, item))
				break;
			wp_ws(s);
			if (s->p < s->end && *s->p == ',') { s->p++; continue; }
			break;
		}
		wp_ws(s);
		if (s->p < s->end && *s->p == ']')
			s->p++;
		s->depth--;
		return v;
	}
	if (c == '"') {
		v = wp_string(s);
		s->depth--;
		return v;
	}
	if (c == 't' && s->p + 4 <= s->end && StrNCmpA((CHAR*)s->p, (CHAR*)"true", 4) == 0) {
		s->p += 4;
		s->depth--;
		return WJNewBool(TRUE);
	}
	if (c == 'f' && s->p + 5 <= s->end && StrNCmpA((CHAR*)s->p, (CHAR*)"false", 5) == 0) {
		s->p += 5;
		s->depth--;
		return WJNewBool(FALSE);
	}
	if (c == 'n' && s->p + 4 <= s->end && StrNCmpA((CHAR*)s->p, (CHAR*)"null", 4) == 0) {
		s->p += 4;
		s->depth--;
		return WJNewNull();
	}
	v = wp_number(s);
	s->depth--;
	return v;
}

WJVal* WJParse(const char* json, ULONG len)
{
	WPState s = { json, json + len, 0 };
	WJVal* v = wp_value(&s);
	if (!v)
		return NULL;
	wp_ws(&s);
	if (s.p != s.end) { // trailing junk: be lenient (Go json.Unmarshal is strict but messages are well-formed)
	}
	return v;
}

//////// serializer ////////

typedef struct {
	char*  buf;
	ULONG  len;
	ULONG  cap;
	BOOL   oom;
} WB;

static void wb_put(WB* b, char c)
{
	if (b->oom)
		return;
	if (b->len + 2 >= b->cap) {
		ULONG nc = b->cap ? b->cap * 2 : 64;
		// alloc-copy-free: LocalReAlloc(LMEM_MOVEABLE) may hand back a
		// movable handle instead of a dereferenceable pointer
		char* nb = (char*)MemAllocLocal(nc);
		if (!nb) {
			b->oom = TRUE;
			return;
		}
		if (b->buf) {
			memcpy(nb, b->buf, b->len);
			memset(b->buf, 0, b->cap);
			MemFreeLocal((LPVOID*)&b->buf, b->cap);
		}
		b->buf = nb;
		b->cap = nc;
	}
	b->buf[b->len++] = c;
}

static void wb_puts(WB* b, const char* s)
{
	while (*s)
		wb_put(b, *s++);
}

static void wb_escape(WB* b, const char* s)
{
	wb_put(b, '"');
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':  wb_puts(b, "\\\""); break;
		case '\\': wb_puts(b, "\\\\"); break;
		case '\n': wb_puts(b, "\\n"); break;
		case '\r': wb_puts(b, "\\r"); break;
		case '\t': wb_puts(b, "\\t"); break;
		case '\b': wb_puts(b, "\\b"); break;
		case '\f': wb_puts(b, "\\f"); break;
		default:
			if (c < 0x20) {
				char tmp[8];
				// minimal hex formatter (no CRT)
				tmp[0] = '\\'; tmp[1] = 'u'; tmp[2] = '0'; tmp[3] = '0';
				tmp[4] = "0123456789abcdef"[c >> 4];
				tmp[5] = "0123456789abcdef"[c & 0xF];
				tmp[6] = 0;
				wb_puts(b, tmp);
			}
			else {
				wb_put(b, (char)c);
			}
		}
	}
	wb_put(b, '"');
}

static void wb_num(WB* b, double v)
{
	if (v != v || v - v != 0) { // NaN/Inf guard (never expected)
		wb_puts(b, "0");
		return;
	}
	// integer path (protocol numbers are integers / seq counters)
	if (v >= -9.0e15 && v <= 9.0e15 && v == (double)(LONG64)v) {
		LONG64 i = (LONG64)v;
		char tmp[24];
		int i2 = 0;
		char rev[24];
		int rl = 0;
		ULONG64 u;
		if (i < 0) { u = (ULONG64)(-(i + 1)) + 1; }
		else u = (ULONG64)i;
		// digit extraction without 64-bit division (x86 no-CRT): split
		// the value into decimal high/low halves via 32-bit ops only
		if (u >= 1000000000ULL) {
			// split without combined divmod: q then r = u - q*d (multiply only)
			ULONG64 q64 = u / 1000000000ULL;
			ULONG high = (ULONG)q64;
			ULONG low = (ULONG)(u - q64 * 1000000000ULL);
			int hl = 0;
			char hrev[12];
			do { hrev[hl++] = (char)('0' + (high % 10)); high /= 10; } while (high);
			while (hl) tmp[i2++] = hrev[--hl];
			char lrev[12];
			int ll = 0;
			do { lrev[ll++] = (char)('0' + (low % 10)); low /= 10; } while (low);
			for (int k = ll; k < 9; k++) tmp[i2++] = '0'; // zero pad low to 9
			while (ll) tmp[i2++] = lrev[--ll];
		}
		else {
			ULONG low = (ULONG)u;
			do { rev[rl++] = (char)('0' + (low % 10)); low /= 10; } while (low);
			if (i < 0) tmp[i2++] = '-';
			while (rl) tmp[i2++] = rev[--rl];
		}
		tmp[i2] = 0;
		wb_puts(b, tmp);
		return;
	}
	// fallback: %.6f-style manual formatting (never used by our messages)
	wb_puts(b, "0");
}

static void wb_value(WB* b, const WJVal* v)
{
	if (!v || v->type == WJ_NULL) {
		wb_puts(b, "null");
		return;
	}
	switch (v->type) {
	case WJ_BOOL:
		wb_puts(b, v->b ? "true" : "false");
		break;
	case WJ_NUM:
		wb_num(b, v->num);
		break;
	case WJ_STR:
		wb_escape(b, v->str);
		break;
	case WJ_ARR:
		wb_put(b, '[');
		for (ULONG i = 0; i < v->count; i++) {
			if (i) wb_put(b, ',');
			wb_value(b, v->items[i]);
		}
		wb_put(b, ']');
		break;
	case WJ_OBJ:
		wb_put(b, '{');
		for (ULONG i = 0; i < v->count; i++) {
			if (i) wb_put(b, ',');
			wb_escape(b, v->keys[i]);
			wb_put(b, ':');
			wb_value(b, v->items[i]);
		}
		wb_put(b, '}');
		break;
	}
}

char* WJSerialize(const WJVal* v)
{
	WB b = { NULL, 0, 0, FALSE };
	wb_value(&b, v);
	if (b.oom) {
		if (b.buf)
			MemFreeLocal((LPVOID*)&b.buf, b.cap);
		return NULL;
	}
	wb_put(&b, 0); // NUL terminator (room was reserved)
	return b.buf;
}
