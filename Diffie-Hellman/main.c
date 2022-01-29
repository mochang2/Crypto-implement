#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/bn.h>

#define NUM_OF_SMALL_PRIMES 70  // the fastest num I feel
#define NUM_OF_Q_TEST 10
#define NUM_OF_P_TEST 3

// create DH secret arguments
typedef struct _b10dh_param_st {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
}BOB10_DH_PARAM;

typedef struct _b10dh_keypair_st {
    BIGNUM *prk;
    BIGNUM *puk;
}BOB10_DH_KEYPAIR;

BN_ULONG small_primes[NUM_OF_SMALL_PRIMES] = {
    3,  5,  7,  11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59,	61,	67,	71,	73,
    79,	83,	89,	97,	101,103,107,109,113,127,
    131,137,139,149,151,157,163,167,173,179,
    181,191,193,197,199,211,223,227,229,233,
    239,241,251,257,263,269,271,277,281,283,
    293,307,311,313,317,331,337,347,349,353,
};

BOB10_DH_PARAM *BOB10_DH_PARAM_new();
BOB10_DH_KEYPAIR *BOB10_DH_KEYPAIR_new();
int BOB10_DH_PARAM_free(BOB10_DH_PARAM *b10dhp);
int BOB10_DH_KEYPAIR_free(BOB10_DH_KEYPAIR *b10dhk);
void BOB10_DH_ParamGenPQ(BOB10_DH_PARAM *dhp, int pBits, int qBits);
void BOB10_DH_ParamGenG(BOB10_DH_PARAM *dhp);
void BOB10_DH_KeypairGen(BOB10_DH_KEYPAIR *dhk,BOB10_DH_PARAM *dhp);
void BOB10_DH_Derive(BIGNUM *sharedSecret, BIGNUM *peerKey, BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp);

void printBN(char* msg, BIGNUM* a);
// test a prime number
bool MillerRabin(BIGNUM* probprime, int cnt, int nBits);
void ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);
bool SmallPrimeTest(BIGNUM* probprime);


int main (int argc, char *argv[]) {
    time_t start, end; double result; start = time(NULL);

    BIGNUM *sharedSecret = BN_new();
    BOB10_DH_PARAM *dhp = BOB10_DH_PARAM_new();
    BOB10_DH_KEYPAIR *aliceK = BOB10_DH_KEYPAIR_new();
    BOB10_DH_KEYPAIR *bobK = BOB10_DH_KEYPAIR_new();

    BOB10_DH_ParamGenPQ(dhp, 2048, 256);
    printf("p=0x");BN_print_fp(stdout,dhp->p);printf("\n");
    printf("q=0x");BN_print_fp(stdout,dhp->q);printf("\n");
    BOB10_DH_ParamGenG(dhp);
    printf("g=0x");BN_print_fp(stdout,dhp->g);printf("\n");

    BOB10_DH_KeypairGen(aliceK,dhp);
    printf("alicePuk=0x");BN_print_fp(stdout,aliceK->puk);printf("\n");
    printf("alicePrk=0x");BN_print_fp(stdout,aliceK->prk);printf("\n");

    BOB10_DH_KeypairGen(bobK,dhp);
    printf("bobPuk=0x");BN_print_fp(stdout,bobK->puk);printf("\n");
    printf("bobPrk=0x");BN_print_fp(stdout,bobK->prk);printf("\n");


    BOB10_DH_Derive(sharedSecret, bobK->puk, aliceK, dhp);
    printf("SS1=0x");BN_print_fp(stdout,sharedSecret);printf("\n");
    BOB10_DH_Derive(sharedSecret, aliceK->puk, bobK, dhp);
    printf("SS2=0x");BN_print_fp(stdout,sharedSecret);printf("\n");

    BOB10_DH_PARAM_free(dhp);
    BOB10_DH_KEYPAIR_free(aliceK);
    BOB10_DH_KEYPAIR_free(bobK);
    BN_free(sharedSecret);

    end = time(NULL);
    result = (double)(end - start);
    printf("It takes %f seconds", result);

    return 0;
}


BOB10_DH_PARAM *BOB10_DH_PARAM_new() {
    BOB10_DH_PARAM* dhp_gpq = malloc(sizeof(BOB10_DH_PARAM));
    dhp_gpq->g = BN_new();
    dhp_gpq->p = BN_new();
    dhp_gpq->q = BN_new();
    return dhp_gpq;
}

BOB10_DH_KEYPAIR *BOB10_DH_KEYPAIR_new() {
    BOB10_DH_KEYPAIR* kp_pubpri = malloc(sizeof(BOB10_DH_KEYPAIR));
    kp_pubpri->puk = BN_new();
    kp_pubpri->prk = BN_new();
    return kp_pubpri;
}

int BOB10_DH_PARAM_free(BOB10_DH_PARAM *b10dhp) {
    if (b10dhp->g != NULL) BN_free(b10dhp->g);
    if (b10dhp->p != NULL) BN_free(b10dhp->p);
    if (b10dhp->q != NULL) BN_free(b10dhp->q);
    return 0;
}

int BOB10_DH_KEYPAIR_free(BOB10_DH_KEYPAIR *b10dhk) {
    if (b10dhk->prk != NULL) BN_free(b10dhk->prk);
    if (b10dhk->puk != NULL) BN_free(b10dhk->puk);
    return 0;
}

void BOB10_DH_ParamGenPQ(BOB10_DH_PARAM *dhp, int pBits, int qBits){
    // p(2048) = q(256) * j(1793) + 1
    // prime = prime * even + 1
    BIGNUM* prime_p = BN_new();
    BIGNUM* prime_q = BN_new();
    BIGNUM* even_j = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    while(true) {
        BN_rand(prime_q, qBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        if (MillerRabin(prime_q, NUM_OF_Q_TEST, qBits)) break;
    }
    BN_copy(dhp->q, prime_q);

    int jBits = pBits - qBits;
    while(true) {
        BN_rand(even_j, jBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        if (BN_is_odd(even_j) == 1) continue; // if even
        BN_mul(prime_p, prime_q, even_j, ctx);
        BN_add_word(prime_p, 1);
        if (!SmallPrimeTest(prime_p)) continue;
        // printBN("p", prime_p);
        if (MillerRabin(prime_p, NUM_OF_P_TEST, pBits)) break;
    }
    BN_copy(dhp->p, prime_p);

    if (prime_p != NULL) BN_free(prime_p);
    if (prime_q != NULL) BN_free(prime_q);
    if (even_j != NULL) BN_free(even_j);
    if(ctx != NULL) BN_CTX_free(ctx);
}

void BOB10_DH_ParamGenG(BOB10_DH_PARAM *dhp) {
    // p - 1 = q * j
    // g^(p - 1) = 1  <=>  g^((p - 1)/2) = -1 // just for calculating real g(bob10_dh_g)
    // if the above is satisfied, real g = g^j
    BIGNUM* p_minus_one = BN_new();
    BIGNUM* power_of_g = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* primitive_g = BN_new();
    BIGNUM* remainder = BN_new();
    BIGNUM* bob10_dh_j = BN_new();
    BIGNUM* bob10_dh_g = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    bool g_found = false;

    BN_one(one);
    BN_set_word(primitive_g, 2);
    BN_sub(p_minus_one, dhp->p, one);
    BN_div(power_of_g, NULL, p_minus_one, primitive_g, ctx);  // (p - 1) / 2
    BN_div(bob10_dh_j, NULL, p_minus_one, dhp->q, ctx);

    while (!g_found) {
        ExpMod(remainder, primitive_g, power_of_g, dhp->p);
        if(BN_cmp(remainder, p_minus_one) == 0) g_found = true;  // if g^((p - 1)/2) == p - 1 (in mod p)
        else BN_add_word(primitive_g, 1);
    }
    ExpMod(bob10_dh_g, primitive_g, bob10_dh_j, dhp->p);
    BN_copy(dhp->g, bob10_dh_g);

    if (p_minus_one != NULL) BN_free(p_minus_one);
    if (power_of_g != NULL) BN_free(power_of_g);
    if (one != NULL) BN_free(one);
    if (primitive_g != NULL) BN_free(primitive_g);
    if (remainder != NULL) BN_free(remainder);
    if (bob10_dh_j != NULL) BN_free(bob10_dh_j);
    if (bob10_dh_g != NULL) BN_free(bob10_dh_g);
    if (ctx != NULL) BN_CTX_free(ctx);
}

void BOB10_DH_KeypairGen(BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp) {
    // random number -> private parameter(power of g)
    srand((unsigned int)time(NULL));
    int prk_bits = rand() % 20 + 2;  // no reason in specific numbers
    BN_rand(dhk->prk, prk_bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);

    // public parameter(g^a mod p)
    BIGNUM* remainder = BN_new();
    ExpMod(remainder, dhp->g, dhk->prk, dhp->p);
    BN_copy(dhk->puk, remainder);

    if (remainder != NULL) BN_free(remainder);
}

void BOB10_DH_Derive(BIGNUM *sharedSecret, BIGNUM *peerKey, BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp) {
    ExpMod(sharedSecret, peerKey, dhk->prk, dhp->p);
}

void printBN(char *msg, BIGNUM *a){
    char *number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// test a prime number
bool MillerRabin(BIGNUM* probprime, int cnt, int nBits){
    // BIGNUM *probprime = BN_new();                   // p
    BIGNUM *probprime_minus_1 = BN_new();           // p-1
    BIGNUM *odd_num_expression = BN_new();          // q
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *remainder_to_decide_to_pass_or_do_not = BN_new();   // a ^ q mod p
    BIGNUM *rnd_base = BN_new();                    // a
    BIGNUM *rnd_power = BN_new();                   // 2^(k - 1) * q
    BN_CTX *ctx = BN_CTX_new();

    bool complex_num_flag = false;
    BN_one(one);
    BN_set_word(two, 2);

    int i = 1;
    while(i != cnt){
        BN_rand(rnd_base, nBits - 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY); // set a, 2nd parameter can be anything
        BN_sub(probprime_minus_1, probprime, one);
        int k = 0;

        while (!BN_is_bit_set(probprime_minus_1, 0)){ // if even
            BN_div_word(probprime_minus_1, 2);
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
            BN_set_word(bn_j, j);

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
        if (i != cnt && j >= k){
            complex_num_flag = true;
            break;
        }
    }

    if(probprime_minus_1 != NULL) BN_free(probprime_minus_1);
    if(odd_num_expression != NULL) BN_free(odd_num_expression);
    if(one != NULL) BN_free(one);
    if(two != NULL) BN_free(two);
    if(remainder_to_decide_to_pass_or_do_not != NULL) BN_free(remainder_to_decide_to_pass_or_do_not);
    if(rnd_base != NULL) BN_free(rnd_base);
    if(rnd_power != NULL) BN_free(rnd_power);
    if(ctx != NULL) BN_CTX_free(ctx);

    if (complex_num_flag) return false;
    return true;
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

bool SmallPrimeTest(BIGNUM* probprime) {
    for (int i = 0; i < NUM_OF_SMALL_PRIMES; i++) {
        if (BN_mod_word(probprime, small_primes[i]) == 0) return false;
    }

    return true;
}






