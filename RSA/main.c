#include "stdafx.h"
#include "modFunc.h"
#include "RSAFunc.h"

int main(int argc, char **argv){
    BOB10_RSA *b10rsa = BOB10_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB10_RSA_KeyGen(b10rsa,1024);
        BN_print_fp(stdout,b10rsa->n);
        printf(" ");
        BN_print_fp(stdout,b10rsa->e);
        printf(" ");
        BN_print_fp(stdout,b10rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b10rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b10rsa->e, argv[2]);
            BOB10_RSA_Enc(out,in, b10rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b10rsa->d, argv[2]);
            BOB10_RSA_Dec(out,in, b10rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b10rsa!= NULL) BOB10_RSA_free(b10rsa);


    return 0;

}
