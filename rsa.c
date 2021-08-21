#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdbool.h>

#define LONG_LONG_MAX 9223372036854775807
#define MIN_COUNT_TO_PROVE_PRIME 10

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
BIGNUM *GenProbPrime(int nBits, bool two_MSB_must_be_one);
void itoa(int num, char *str, int base);

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
    BIGNUM *phi_n = BN_new();
    BIGNUM *phi_n_tmp = BN_new();
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_q = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *euclid_tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // n = p * q
    bn_p = GenProbPrime(nBits/2, 1);
    bn_q = GenProbPrime(nBits/2, 0);
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

BIGNUM *GenProbPrime(int nBits, bool two_MSB_must_be_one){
    BIGNUM *probprime = BN_new();                   // p
    BIGNUM *probprime_minus_1 = BN_new();           // p-1
    BIGNUM *odd_num_expression = BN_new();          // q
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *remainder_to_decide_to_pass_or_do_not = BN_new();   // a ^ q mod p
    BIGNUM *rnd_base = BN_new();                    // a
    BIGNUM *rnd_power = BN_new();                   // 2^(k - 1) * q
    BN_CTX *ctx = BN_CTX_new();

    bool sufficient_examination = false;
    BN_dec2bn(&one, "1");
    BN_dec2bn(&two, "2");

    while (!sufficient_examination){
        if (two_MSB_must_be_one)
            BN_rand(probprime, nBits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY);
        else
            BN_rand(probprime, nBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        int i = 1;

        while(i != MIN_COUNT_TO_PROVE_PRIME){  // => 10 to change
            BN_rand(rnd_base, 20, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY); // set a, 2nd parameter can be anything
            BN_sub(probprime_minus_1, probprime, one);
            int k = 0;

            while (!BN_is_bit_set(probprime_minus_1, 0)){ // if even
                BN_div(probprime_minus_1, NULL, probprime_minus_1, two, ctx);
                k++;
            } // p - 1 = 2 ^ k * odd_num_expression
            BN_copy(odd_num_expression, probprime_minus_1);
            BN_sub(probprime_minus_1, probprime, one); // reallocate(p - 1 == -1) in mod p

            int j;
            for (j = 0; j <= k; j++){
                if (j == k && k != 0)
                    break;

                // int to BN => need a function
                BIGNUM *bn_j = BN_new();
                char* str = (char*)malloc(sizeof(int));
                itoa(j, str, 10);
                BN_dec2bn(&bn_j, str);
                free(str);

                BN_exp(rnd_power, two, bn_j, ctx);
                BN_mul(rnd_power, rnd_power, odd_num_expression, ctx);

                ExpMod(remainder_to_decide_to_pass_or_do_not, rnd_base, rnd_power, probprime);

                if(j == 0 && (BN_cmp(remainder_to_decide_to_pass_or_do_not, one) == 0)){ // maybe prime
                    i++;
                    break;
                }

                if(BN_cmp(remainder_to_decide_to_pass_or_do_not, probprime_minus_1) == 0){ // maybe prime
                    i++;
                    break;
                }
            }
            if(i == MIN_COUNT_TO_PROVE_PRIME)
                sufficient_examination = true;

            if (j >= k)
                break;
        }
    }

    if(probprime_minus_1 != NULL) BN_free(probprime_minus_1);
    if(odd_num_expression != NULL) BN_free(odd_num_expression);
    if(two != NULL) BN_free(two);
    if(one != NULL) BN_free(one);
    if(remainder_to_decide_to_pass_or_do_not != NULL) BN_free(remainder_to_decide_to_pass_or_do_not);
    if(rnd_base != NULL) BN_free(rnd_base);
    if(rnd_power != NULL) BN_free(rnd_power);
    if(ctx != NULL) BN_CTX_free(ctx);

    return probprime;
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
}

