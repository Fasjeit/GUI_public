
#include "sizes.h"

#include "run_config.h"
#if defined(_NO_OPENSSL_)
#include "crand.h"
#else
#include <openssl/rand.h>
#endif

#include "quartz.h"

#include "quartz.hpp"

extern "C" int keypair(unsigned char sk[SECRETKEY_BYTES], unsigned long long *sklen, unsigned char pk[PUBLICKEY_BYTES], unsigned long long *pklen)
{
	quartz_pub_key_t pkey;
	quartz_sec_key_t skey;

	quartz_gen_key(pkey, skey);

	pkey.dump(pk);
	skey.dump(sk);

	*sklen = quartz_sec_key_t::num_byte();
	*pklen = quartz_pub_key_t::num_byte();

	return 0;
}

extern "C" int signatureofshorthash(unsigned char sm[SIGNATURE_BYTES], unsigned long long *smlen,
									const unsigned char m[SHORTHASH_BYTES], const unsigned long long mlen,
									const unsigned char sk[SECRETKEY_BYTES], const unsigned long long sklen)
{
	if (sklen != SECRETKEY_BYTES)
		return -11;
	if (mlen != SHORTHASH_BYTES)
		return -12;

	quartz_sec_key_t skey;
	skey.set(sk);

	vec_sign_t signature;
	quartz_sign<REPEAT>(signature, m, skey);

	signature.dump(sm);
	*smlen = vec_sign_t::num_byte();

	return 0;
}

extern "C" int signatureofshorthash_mq(unsigned char sm[SIGNATURE_BYTES], unsigned long long *smlen,
									   const unsigned char m[SHORTHASH_BYTES], const unsigned long long mlen,
									   const unsigned char sk[SECRETKEY_BYTES], const unsigned long long sklen,
									   unsigned char sigma_s[M], unsigned char x[MINUS + VINEGAR])
{
	if (sklen != SECRETKEY_BYTES)
		return -11;
	if (mlen != SHORTHASH_BYTES)
		return -12;

	quartz_sec_key_t skey;
	skey.set(sk);

	vec_sign_t signature;
	quartz_sign_mq<REPEAT>(signature, m, skey, sigma_s, x);

	signature.dump(sm);
	*smlen = vec_sign_t::num_byte();

	return 0;
}

extern "C" int sign_gui_fnr(
	unsigned char *nonce,
	unsigned long noncelen,
	const unsigned char *key_material,
	const unsigned long key_materiallen,
	const unsigned char sk[SECRETKEY_BYTES],
	unsigned long long sklen,
	unsigned char s[M / 8 + 1],
	unsigned long long slen,
	unsigned char x[(MINUS + VINEGAR) * REPEAT / 8 + 1],
	unsigned long long xlen)
{
	if (sklen != SECRETKEY_BYTES)
		return -11;
	// if (key_materiallen <= PUBKEY_BYTES)
	// 	return -12;
	if (slen != M / 8 + 1)
		return -13;
	if (xlen != (MINUS + VINEGAR) * REPEAT / 8 + 1)
		return -14;

	quartz_sec_key_t skey;
	skey.set(sk);

	return quartz_sign_gui_fnr<REPEAT>(
		nonce,
		noncelen,
		key_material,
		key_materiallen,
		skey,
		s,
		x);
}

extern "C" int verify_gui_fnr(
	unsigned char *nonce,
	unsigned long noncelen,
	const unsigned char *key_material,
	const unsigned long key_materiallen,
	const unsigned char pk[PUBKEY_BYTES],
	unsigned long long pklen,
	unsigned char s[M / 8 + 1],
	unsigned long long slen,
	unsigned char x[(MINUS + VINEGAR) * REPEAT / 8 + 1],
	unsigned long long xlen)
{
	if (pklen != PUBKEY_BYTES)
		return -11;
	// if (key_materiallen <= PUBKEY_BYTES)
	// 	return -12;
	if (slen != M / 8 + 1)
		return -13;
	if (xlen != (MINUS + VINEGAR) * REPEAT / 8 + 1)
		return -14;

	quartz_pub_key_t pkey;
	pkey.set(pk);

	return quartz_verify_gui_fnr<REPEAT>(
		nonce,
		noncelen,
		key_material,
		key_materiallen,
		pkey,
		s,
		x);
}

extern "C" int
hfev(
	const unsigned char sk[SECRETKEY_BYTES],
	unsigned long long sklen,
	unsigned char s[M / 8 + 1],
	unsigned long long slen,
	unsigned char x[(MINUS + VINEGAR) / 8 + 1],
	unsigned long long xlen)
{
	if (sklen != SECRETKEY_BYTES)
		return -11;
	if (slen != M / 8 + 1)
		return -12;
	if (xlen != (MINUS + VINEGAR) / 8 + 1)
		return -13;

	quartz_sec_key_t skey;
	skey.set(sk);

	return quartz_sign_hfev<0, 0>(skey, s, x);
}

extern "C" int hfev_inv(
	const unsigned char pk[PUBKEY_BYTES],
	unsigned long long pkLen,
	unsigned char s[M / 8 + 1],
	unsigned long long slen,
	unsigned char x[(MINUS + VINEGAR) / 8 + 1],
	unsigned long long xlen)
{
	if (pkLen != PUBKEY_BYTES)
		return -11;
	if (slen != M / 8 + 1)
		return -12;
	if (xlen != (MINUS + VINEGAR) / 8 + 1)
		return -13;

	quartz_pub_key_t pkey;
	pkey.set(pk);

	return quartz_validate_hfev<0, 0>(pkey, s, x);
}

extern "C" int verification(const unsigned char m[SHORTHASH_BYTES], const unsigned long long mlen,
							const unsigned char sm[SIGNATURE_BYTES], const unsigned long long smlen,
							const unsigned char pk[PUBLICKEY_BYTES], const unsigned long long pklen)
{
	if (smlen != SIGNATURE_BYTES)
		return -101;
	if (mlen != SHORTHASH_BYTES)
		return -102;
	if (pklen != PUBLICKEY_BYTES)
		return -103;

	quartz_pub_key_t pkey;
	pkey.set(pk);

	vec_sign_t signature(sm);

	return quartz_verify<REPEAT>(m, signature, pkey);
}

extern "C" void crypto_hash_sha256_c(unsigned char *h, const unsigned char *m, unsigned long long mlen)
{
	crypto_hash_sha256(h, m, mlen);
}
