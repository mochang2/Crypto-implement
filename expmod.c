#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a){
	char *number_str = BN_bn2dec(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

void ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
	BIGNUM *A = BN_new();
	BIGNUM *shift_tmp = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	
	BN_copy(A, a);

	for (int i = BN_num_bits(e) - 2; i >= 0; i--){
		BN_rshift(shift_tmp, e, i);
		int is_one = BN_is_bit_set(shift_tmp, 0);
		//printf("%d\n", is_one);

		if (is_one){
			BN_sqr(A, A, ctx);
			BN_mul(A, A, a, ctx);
			BN_mod(A, A, m, ctx);
			//printBN("value ", A);
		}
		else{
			BN_sqr(A, A, ctx);
			BN_mod(A, A,  m, ctx);
			//printBN("value ", A);
		}
	}

	BN_copy(r, A);

	if(A != NULL) BN_free(A);
	if(shift_tmp != NULL) BN_free(shift_tmp);
	if(ctx != NULL) BN_CTX_free(ctx);
}

int main(int argc, char **argv){
	BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

	BN_dec2bn(&a, argv[1]);
	BN_dec2bn(&e, argv[2]);
	BN_dec2bn(&m, argv[3]);
	printBN("a = ", a);
	printBN("e = ", e);
	printBN("m = ", m);

	ExpMod(res, a, e, m);

	printBN("a**e mod m = ", res);

	
        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}
