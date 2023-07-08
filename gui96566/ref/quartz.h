
#ifndef _QUARTZ_H_
#define _QUARTZ_H_

#include "config.h"
#include "sizes.h"

// #ifdef __cplusplus
extern "C"
{
  // #endif

  int keypair(unsigned char sk[SECRETKEY_BYTES], unsigned long long *sklen, unsigned char pk[PUBLICKEY_BYTES],
              unsigned long long *pklen);

  int signatureofshorthash(unsigned char *, unsigned long long *,
                           const unsigned char *, unsigned long long,
                           const unsigned char *, unsigned long long);

  int signatureofshorthash_mq(unsigned char *, unsigned long long *,
                              const unsigned char *, unsigned long long,
                              const unsigned char *, unsigned long long,
                              unsigned char *sigma_s, unsigned char *x);

  int verification(const unsigned char *, unsigned long long,
                   const unsigned char *, unsigned long long,
                   const unsigned char *, unsigned long long);

  int hfev(
      const unsigned char *sk,
      unsigned long long sklen,
      unsigned char *s,
      unsigned long long slen,
      unsigned char *x,
      unsigned long long xlen);

  int hfev_inv(
      const unsigned char *pk,
      unsigned long long pklen,
      unsigned char *s,
      unsigned long long slen,
      unsigned char *x,
      unsigned long long xlen);

  // #ifdef __cplusplus
}
// #endif

#endif
