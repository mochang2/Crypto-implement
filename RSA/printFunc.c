#include "stdafx.h"
#include "printFunc.h"

void printBN(char *msg, BIGNUM *a){
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

void PrintUsage(){
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}
