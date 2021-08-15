#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

#define LONG_LONG_MAX 9223372036854775807

typedef struct _b10rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
} BOB10_RSA;

BOB10_RSA *BOB10_RSA_new();
int BOB10_RSA_free(BOB10_RSA *b10rsa);
int BOB10_RSA_KeyGen(BOB10_RSA *b10rsa, int nBits);
int BOB10_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB10_RSA *b10rsa);
int BOB10_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB10_RSA *b10rsa);
void PrintUsage();
void ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);
BIGNUM *XEuclid(BIGNUM *x, const BIGNUM *a, const BIGNUM *b);
BIGNUM *euclid(BIGNUM *a, BIGNUM *b);


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

BOB10_RSA *BOB10_RSA_new(){
    BOB10_RSA* b10rsa_edn = malloc(sizeof(BOB10_RSA));
    b10rsa_edn->e = BN_new();
    b10rsa_edn->d = BN_new();
    b10rsa_edn->n = BN_new();

    return b10rsa_edn;
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

void PrintUsage(){
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

void ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
    BIGNUM *A = BN_new();
    BIGNUM *shift_tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_copy(A, a);

    for (int i = BN_num_bits(e) - 2; i >= 0; i--){
        BN_rshift(shift_tmp, e, i);
        int is_one = BN_is_bit_set(shift_tmp, 0);

        if (is_one){
            BN_sqr(A, A, ctx);
            BN_mul(A, A, a, ctx);
            BN_mod(A, A, m, ctx);
        }
        else{
            BN_sqr(A, A, ctx);
            BN_mod(A, A,  m, ctx);
        }
    }

    BN_copy(r, A);

    if(A != NULL) BN_free(A);
    if(shift_tmp != NULL) BN_free(shift_tmp);
    if(ctx != NULL) BN_CTX_free(ctx);
}

BIGNUM *XEuclid(BIGNUM *x, const BIGNUM *a, const BIGNUM *b){
    BIGNUM *q = BN_new();	// share
    BIGNUM *r1 = BN_new();	// numerator
    BIGNUM *r2 = BN_new();	// denominator
    BIGNUM *r = BN_new();	// remainder
    BIGNUM *x1 = BN_new();	// antece-antecedent of x
    BIGNUM *x2 = BN_new();	// antecedent of x
    BIGNUM *tmpx = BN_new();
    // x = x1 - x2 * q
    BIGNUM *zero = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // initialize
    BN_copy(r1, a);
    BN_copy(r2, b);
    BN_dec2bn(&x1, "1");
    BN_dec2bn(&x2, "0");
    BN_dec2bn(&zero, "0");

    while (!BN_is_one(r)) { // while(r != one)
        // x = x1 - q * x2
        // y = y1 - q * y2
        BN_div(q, r ,r1, r2, ctx);
        BN_mul(tmpx, q, x2, ctx);
        BN_sub(x, x1, tmpx);

        // r1 <- r2, r2 <- r, x1 <- x2, x2 <- x, y1 <- y2, y2 <- y
        BN_copy(r1, r2);
        BN_copy(r2, r);
        BN_copy(x1, x2);
        BN_copy(x2, x);
    }

    if(BN_cmp(zero, x) == 1){
        // b is dividing number
        BN_add(x, x, b);
    }

    if(q != NULL) BN_free(q);
    if(r != NULL) BN_free(r);
    if(r1 != NULL) BN_free(r1);
    if(r2 != NULL) BN_free(r2);
    if(x1 != NULL) BN_free(x1);
    if(x2 != NULL) BN_free(x2);
    if(tmpx != NULL) BN_free(tmpx);
    if(ctx != NULL) BN_CTX_free(ctx);

    return x;
}

BIGNUM *euclid(BIGNUM *a, BIGNUM *b)
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *r = BN_new();
  BIGNUM *t;

  if (BN_cmp(a, b) < 0) {
     t = a;
     a = b;
     b = t;
  }

  while (!BN_is_zero(b)) {
        if(!BN_mod(r,a,b,ctx)){
          goto err;
        }
        BN_copy(a,b);
        BN_copy(b,r);
  }
  BN_copy(r,a);
  if(ctx != NULL) BN_CTX_free(ctx);

  return r;
err:
  return NULL;
}
