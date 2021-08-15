#include "stdafx.h"
#include "modFunc.h"
#include "printFunc.h"

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
