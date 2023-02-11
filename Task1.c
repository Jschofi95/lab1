/* Task1.c */
#include <stdio.h>
#include <openssl/bn.h>

void printBN (char *msg, BIGNUM *a) {
    // Convert the BIGNUM to number string
    char * number_str = BN_bn2hex(a);

    // Print out the number string
    printf("%s %s\n", msg, number_str);

    // Free the dynamically allocated memory
    OPENSSL_free(number_str);
}

int main() {
    // BIGNUM temporary variable
    BN_CTX *ctx = BN_CTX_new();

    // Initalize p, q, e, n, d
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    // Private key
    BIGNUM *d = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // n = p * q
    BN_mul(n, p, q, ctx);

    // Private key = de(mod(Phi(N))) = 1
    // Fi(N) = (p - 1)(q - 1)

    BIGNUM *Phi = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *pMinusOne = BN_new();
    BIGNUM *qMinusOne = BN_new();

    BN_dec2bn(&one, "1");
    BN_sub(pMinusOne, p, one);
    BN_sub(qMinusOne, q, one);
    BN_mul(Phi, pMinusOne, qMinusOne, ctx);

    // Get private key
    BN_mod_inverse(d, e, Phi, ctx);

    // Print private key
    printBN("Private key d =", d);

    return 0;
}