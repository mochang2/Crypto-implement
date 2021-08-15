#include "stdafx.h"
#include "RSAFunc.h"
#include "modFunc.h"
#include "printFunc.h"

#define LONG_LONG_MAX 9223372036854775807

BOB10_RSA *BOB10_RSA_new(){
    BOB10_RSA* b10rsa_edn = malloc(sizeof(BOB10_RSA));
    b10rsa_edn->e = BN_new();
    b10rsa_edn->d = BN_new();
    b10rsa_edn->n = BN_new();

    return b10rsa_edn;
}

int BOB10_RSA_free(BOB10_RSA *b10rsa){
    if(b10rsa->e != NULL)
        BN_free(b10rsa->e);
    else
        return -1;
    if(b10rsa->d != NULL)
        BN_free(b10rsa->d);
    else
        return -1;
    if(b10rsa->n != NULL)
        BN_free(b10rsa->n);
    else
        return -1;

    free(b10rsa);

    return 0;
}

int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits){
    char *p, *q;
    p="C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875\
E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7";
    q="F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8\
A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F";
    BIGNUM *phi_n = BN_new();
    BIGNUM *phi_n_tmp = BN_new();
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_q = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *euclid_tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // n = p * q
    BN_hex2bn(&bn_p, p);
    BN_hex2bn(&bn_q, q);
    BN_mul(b10rsa->n, bn_p, bn_q, ctx);

    // phi_n = (p - 1) * (q - 1)
    // (e, phi_n) == 1
    BN_hex2bn(&one, "1");
    BN_sub(bn_p, bn_p, one);
    BN_sub(bn_q, bn_q, one);
    BN_mul(phi_n, bn_p, bn_q, ctx);

    char str[20];
    for (long long i = 3; i < LONG_LONG_MAX; i++){
        sprintf(str, "%lld", i);
        BN_dec2bn(&(b10rsa->e), str);
        BN_copy(phi_n_tmp, phi_n);
        euclid_tmp = euclid(phi_n_tmp, b10rsa->e);  // calc gcd

        if (!BN_cmp(euclid_tmp, one))
            break;
    }
    BN_dec2bn(&(b10rsa->e), str);  // I don't know the exact reason but when if comes out from the for loop
                                   // e becomes 0.

    // d * e == 1 (mod phi_n)
    BIGNUM *x = BN_new();
    b10rsa->d = XEuclid(x, b10rsa->e, phi_n);

    if(phi_n != NULL) BN_free(phi_n);
    if(bn_p != NULL) BN_free(bn_p);
    if(bn_q != NULL) BN_free(bn_q);
    if(one != NULL) BN_free(one);
    if(phi_n_tmp != NULL) BN_free(phi_n_tmp);
    if(euclid_tmp != NULL) BN_free(euclid_tmp);
    if(ctx != NULL) BN_CTX_free(ctx);

    return 0;
}

int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa){
    ExpMod(c, m, b10rsa->e, b10rsa->n);

    return 0;
}

int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa){
    ExpMod(m, c, b10rsa->d, b10rsa->n);

    return 0;
}

void itoa(int num, char *str, int base){
    int i=0;
    int deg=1;
    int cnt = 0;

    while(1){
        if( (num/deg) > 0)
            cnt++;
        else
            break;
        deg *= base;
    }
    deg /=base;
    for(i=0; i<cnt; i++)    {
        *(str+i) = num/deg + '0';
        num -= ((num/deg) * deg);
        deg /=base;
    }
    *(str+i) = '\0';

    for (int i = 0; i < 6 ; i++)
        printf("%d", str[i]);
    printf("\n");
}
