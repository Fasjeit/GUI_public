
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

  // #ifdef __cplusplus
}
// #endif

#endif
