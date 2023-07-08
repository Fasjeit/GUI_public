
#ifndef _QUARTZ_HPP_
#define _QUARTZ_HPP_

#include "quartz_core.h"

#include <bitset>
#include <iostream>

template <unsigned width, unsigned times>
inline void split_hash(VEC<width> hn[], const uint8_t *sha256_dig)
{
	typedef VEC<width> vec_t;
	const uint64_t *dig1 = (const uint64_t *)sha256_dig;
	uint64_t dig2[8] __attribute__((aligned(32))) = {0}; /// 32 byte = 256 bit
	crypto_hash_sha256((uint8_t *)dig2, (const uint8_t *)sha256_dig, 32);

	hn[0] = vec_t(sha256_dig);
	hn[1] = vec_t(&sha256_dig[16]);
	hn[2] = vec_t((const uint8_t *)dig2);
	if (3 < times)
		hn[3] = vec_t(&((const uint8_t *)dig2)[16]);
}

#include "quartz_core.h"

typedef VEC<M + REPEAT *(MINUS + VINEGAR)> vec_sign_t;

template <unsigned size>
void dump_dbg(VEC<size> v)
{
	unsigned char res[size];
	v.dump(res);

	unsigned long len = v.num_byte();
	std::string result_inverted[len];

	std::cout << "forward0:\n";
	for (int i = 0; i < len; i++)
	{
		std::string binary = std::bitset<sizeof(char) * 8>(res[i]).to_string(); // to binary
		result_inverted[len - i - 1] = binary;
		std::cout << binary;
	}
	std::cout << "\n";

	std::cout << "reversed1:\n";
	for (int i = 0; i < len; i++)
	{
		std::cout << result_inverted[i];
	}
	std::cout << "\n";
}

template <unsigned times>
int quartz_verify(const unsigned char *hash256, const vec_sign_t &sm, const quartz_pub_key_t &pk)
{
	vec_m_t hn[times];
	split_hash<M, times>(hn, hash256);

	vec_n_t nn = sm.template concate<N>();
	vec_m_t accu_check;
	mpkc_pub_map(accu_check, pk, nn);

	uint64_t tail = sm.template tail<(times - 1) * (MINUS + VINEGAR)>();
	for (unsigned i = times - 1; i > 0; i--)
	{
		accu_check ^= hn[i];
		nn = accu_check.template concate<N>(tail);
		mpkc_pub_map(accu_check, pk, nn);
		tail >>= (MINUS + VINEGAR);
	}
	if (accu_check == hn[0])
		return 0;
	return -1;
}

template <unsigned times>
int quartz_sign(vec_sign_t &sm, const unsigned char *hash256, const quartz_sec_key_t &sk)
{
	vec_m_t hn[times];
	split_hash<M, times>(hn, hash256);

	uint8_t rand_seed[32];
	uint64_t tail = 0;

	vec_n_t nn;
	vec_m_t accu_mm;

	accu_mm.set_zero();

	for (unsigned i = 0; i < times; i++)
	{
		accu_mm ^= hn[i];
		memset(rand_seed, 0, 32);
		((vec_m_t &)rand_seed) ^= accu_mm;

		quartz_sec_map(nn, sk, accu_mm, rand_seed);

		uint64_t tmp = nn.template tail<MINUS + VINEGAR>();
		tail = (tail << (MINUS + VINEGAR)) | tmp;
		accu_mm = nn.template concate<M>();
	}

	sm = accu_mm.template concate<M + times *(MINUS + VINEGAR)>(tail);

	return 0;
}

template <unsigned times>
int quartz_sign_mq(vec_sign_t &sm, const unsigned char *hash256, const quartz_sec_key_t &sk, unsigned char sigma_s[M], unsigned char x[MINUS + VINEGAR])
{
	vec_m_t hn[times];
	split_hash<M, times>(hn, hash256);

	uint8_t rand_seed[32];
	uint64_t tail = 0;

	vec_n_t nn;
	vec_m_t accu_mm;

	if (sigma_s == NULL)
	{
		accu_mm.set_zero();
	}
	else
	{
		accu_mm = vec_m_t(sigma_s);
	}

	for (unsigned i = 0; i < times; i++)
	{
		// D_i = hm
		// S = accu_mm
		// nn = output (S_i, X_i)
		// tail - seqs of (a-v) bytes of X_i represented as uint64_t (each time shifted)
		// nn - putput of hfev-
		// nn.template concate<M>(); - get fist m bits

		// D_i \oplus S_i
		accu_mm ^= hn[i];
		memset(rand_seed, 0, 32);
		((vec_m_t &)rand_seed) ^= accu_mm;

		quartz_sec_map(nn, sk, accu_mm, rand_seed);

		uint64_t tmp = nn.template tail<MINUS + VINEGAR>();
		tail = (tail << (MINUS + VINEGAR)) | tmp;
		accu_mm = nn.template concate<M>();

		std::string binary = std::bitset<sizeof(uint64_t) * 8>(tmp).to_string(); // to binary
		std::cout << binary << " tmp\n";

		std::string binaryT = std::bitset<sizeof(uint64_t) * 8>(tail).to_string(); // to binary
		std::cout << binaryT << " tail T\n";

		uint64_t acuUintT = accu_mm.template tail<M>();
		std::string accT = std::bitset<sizeof(uint64_t) * 8>(acuUintT).to_string(); // to binary
		std::cout << accT << " tail current accu _mm (S)\n";

		std::cout << "accu_mm tms is:\n";
		dump_dbg<M>(accu_mm);
	}

	sm = accu_mm.template concate<M + times *(MINUS + VINEGAR)>(tail);

	uint64_t acuUint = accu_mm.template tail<M>();
	std::string binaryM = std::bitset<sizeof(uint64_t) * 8>(acuUint).to_string(); // to binary
	std::cout << binaryM << " tail accu_mm (S)\n";

	std::cout << "full accu_mm is:";
	dump_dbg<M>(accu_mm);

	uint64_t smUint = sm.template tail<M + times *(MINUS + VINEGAR)>();
	std::string binarySM = std::bitset<sizeof(uint64_t) * 8>(smUint).to_string(); // to binary
	std::cout << binarySM << " tail SM\n";

	uint64_t smUint2 = sm.template tail<M + times *(MINUS + VINEGAR) - sizeof(uint64_t)>();
	std::string binarySM2 = std::bitset<sizeof(uint64_t) * 8>(smUint).to_string(); // to binary
	std::cout << binarySM2 << " tail SM2\n";

	std::cout << "full SM is:";
	dump_dbg<126>(sm);

	if (sigma_s != NULL)
	{
		accu_mm.dump(sigma_s);
	}

	memcpy(x, &tail, sizeof(tail));

	return 0;
}

template <unsigned width, unsigned times>
int quartz_sign_hfev(
	const quartz_sec_key_t &sk,
	unsigned char s[M / 8 + 1],
	unsigned char x[(MINUS + VINEGAR) / 8 + 1])
{
	uint8_t rand_seed[32];
	uint64_t tail = 0;

	vec_n_t nn;
	vec_m_t accu_mm;

	accu_mm = vec_m_t(s);

	memset(rand_seed, 0, 32);
	((vec_m_t &)rand_seed) ^= accu_mm;

	quartz_sec_map(nn, sk, accu_mm, rand_seed);

	accu_mm = nn.template concate<M>();
	uint64_t tmp = nn.template tail<MINUS + VINEGAR>();

	accu_mm.dump(s);

	memcpy(x, &tmp, (MINUS + VINEGAR) / 8 + 1);

	std::string binary = std::bitset<sizeof(uint64_t) * 8>(tmp).to_string(); // to binary
	std::cout << binary << " tmp\n";

	std::string binaryT = std::bitset<sizeof(uint64_t) * 8>(tail).to_string(); // to binary
	std::cout << binaryT << " tail T\n";

	uint64_t acuUintT = accu_mm.template tail<M>();
	std::string accT = std::bitset<sizeof(uint64_t) * 8>(acuUintT).to_string(); // to binary
	std::cout << accT << " tail current accu _mm (S)\n";

	std::cout << "accu_mm tms is:\n";
	dump_dbg<M>(accu_mm);

	std::cout << "nn all would be is:\n";
	dump_dbg<N>(nn);

	return 0;
}

template <unsigned width, unsigned times>
int quartz_validate_hfev(
	const quartz_pub_key_t &pk,
	unsigned char s[M / 8 + 1],
	unsigned char x[(MINUS + VINEGAR) / 8 + 1])
{
	uint64_t tmp = 0;
	memcpy(&tmp, x, (MINUS + VINEGAR) / 8 + 1);

	vec_n_t nn;
	vec_m_t accu_check;

	accu_check = vec_m_t(s);

	nn = accu_check.concate<M + MINUS + VINEGAR>(tmp);
	mpkc_pub_map(accu_check, pk, nn);

	accu_check.dump(s);

	return 0;
}

#endif /// _QUARTZ_HPP_
