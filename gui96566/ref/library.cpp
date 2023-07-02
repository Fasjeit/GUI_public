#include "library.hpp"
#include "quartz.h"
// #include "library_core.hpp"
#include <stdio.h>

int inc_value(int x)
{
    return x + 1;
    // return inc_value_core(x);
}

int keypairW(unsigned char sk[SECRETKEY_BYTES],
             unsigned long long *sklen,
             unsigned char pk[PUBLICKEY_BYTES],
             unsigned long long *pklen)
{
    return keypair(sk, sklen, pk, pklen);
}