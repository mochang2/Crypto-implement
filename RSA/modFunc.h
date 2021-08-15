#pragma once

#include <openssl/bn.h>

void ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);
BIGNUM *XEuclid(BIGNUM *x, const BIGNUM *a, const BIGNUM *b);
BIGNUM *euclid(BIGNUM *a, BIGNUM *b);
