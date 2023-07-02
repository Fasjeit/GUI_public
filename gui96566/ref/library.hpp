#include "api.h"

#ifndef LIB1_H_INCLUDED
#define LIB1_H_INCLUDED

#ifdef __cplusplus
extern "C"
{
#endif

   int inc_value(int x);

   int keypairW(unsigned char sk[SECRETKEY_BYTES],
                unsigned long long *sklen,
                unsigned char pk[PUBLICKEY_BYTES],
                unsigned long long *pklen);

#ifdef __cplusplus
}
#endif

#endif /* LIB1_H_INCLUDED */
