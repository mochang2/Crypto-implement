#include <stdio.h>
#include <openssl/bn.h>
#include <stdbool.h>

void usage(){
	printf("syntax: xeuclid <num1> <num2>\n");
	printf("sample: xeuclid 123123123111 1293109238019381121\n");
}


bool parse(int argc){
	if (argc != 3){
		usage();
		return false;
	}
	return true;
}

void printBN(char *msg, BIGNUM *a)
{
        /* Use BN_bn2hex(a) for hex string * Use BN_bn2dec(a) for decimal string */
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}


BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b){
	BIGNUM *q = BN_new();	// share
	BIGNUM *r1 = BN_new();	// numerator
	BIGNUM *r2 = BN_new();	// denominator
	BIGNUM *r = BN_new();	// remainder
	BIGNUM *x1 = BN_new();	// antece-antecedent of x
	BIGNUM *x2 = BN_new();	// antecedent of x
	BIGNUM *tmpx = BN_new();
	// x = x1 - x2 * q
	BIGNUM *y1 = BN_new();	// antece-antecedent of y
	BIGNUM *y2 = BN_new();	// antecedent of y
	BIGNUM *tmpy = BN_new();
	// y = y1 - y2 * q	
	BN_CTX *ctx = BN_CTX_new();

	// initialize
	BN_copy(r1, a);
	BN_copy(r2, b);
	BN_dec2bn(&r, "-1");
	BN_dec2bn(&x1, "1");
	BN_dec2bn(&x2, "0");
	BN_dec2bn(&y1, "0");
	BN_dec2bn(&y2, "1");
	
	while (!BN_is_zero(r)) { 
		// x = x1 - q * x2
		// y = y1 - q * y2
		BN_div(q, r ,r1, r2, ctx);
		BN_mul(tmpx, q, x2, ctx);
		BN_mul(tmpy, q, y2, ctx);
		BN_sub(x, x1, tmpx);	
		BN_sub(y, y1, tmpy);
		
		// r1 <- r2, r2 <- r, x1 <- x2, x2 <- x, y1 <- y2, y2 <- y
		BN_copy(r1, r2);
		BN_copy(r2, r);
		BN_copy(x1, x2);
		BN_copy(x2, x);
		BN_copy(y1, y2);
		BN_copy(y2, y);
	}
	if(q != NULL) BN_free(q);
        if(r2 != NULL) BN_free(r2);
        if(r != NULL) BN_free(r);
        if(x1 != NULL) BN_free(x1);
        if(x2 != NULL) BN_free(x2);
        if(y1 != NULL) BN_free(y1);        
        if(y2 != NULL) BN_free(y2);
        if(tmpx != NULL) BN_free(tmpx);
        if(tmpy != NULL) BN_free(tmpy);

	return r1;
}

int main(int argc, char **argv){
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *gcd;

	if(!parse(argc))
		return -1;

	BN_dec2bn(&a, argv[1]);
	BN_dec2bn(&b, argv[2]);
	gcd = XEuclid(x, y, a, b);

	printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);
	
	return 0;
}
