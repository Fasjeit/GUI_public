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

    keypair(sk, &sklen, pk, &pklen);

    printf("hello? %d\n", sklen);

    return 0;
}