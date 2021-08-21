#include "stdafx.h"
#include "printFunc.h"

void printBN(char *msg, BIGNUM *a){
    char *number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}

void PrintUsage(){
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}
