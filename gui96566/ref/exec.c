#include "quartz.h"
#include "quartz.hpp"
#include <stdio.h>

int main()
{
    int r = 0;
    unsigned char sk[SECRETKEY_BYTES];
    unsigned long long sklen = 0;
    unsigned char pk[PUBLICKEY_BYTES];
    unsigned long long pklen = 0;

    unsigned char sm[SIGNATURE_BYTES];
    unsigned long long smlen;

    unsigned char m[SHORTHASH_BYTES];
    unsigned long long mlen = SHORTHASH_BYTES;

    keypair(sk, &sklen, pk, &pklen);
    signatureofshorthash_mq(sm, &smlen, m, mlen, sk, sklen);

    printf("hello??? %d\n", sklen);

    return 0;
}