/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN (char *msg, BIGNUM *a) {
    // Convert the BIGNUM to number string
    char * number_str = BN_bn2dec(a);

    // Print out the number string
    printf("%s %s\n", msg, number_str);

    // Free the dynamically allocated memory
    OPENSSL_free(number_str);
}

int main () {
    // BIGNUM temporary variable
    BN_CTX *ctx = BN_CTX_new();

    // A BIGNUM variable
    BIGNUM *a = BN_new();

    // Assign a value from a decimal number string
    BN_dec2bn(&a, "12345678901112231223");
    printBN("Decimal number string:", a);

    // Assign a value from a hex number string
    BN_hex2bn(&a, "2A3B4C55FF77889AED3F");
    printBN("Hex number string:", a);

    // Generate a random number of 128 bits
    BN_rand(a, 128, 0, 0);
    printBN("Random number of 128 bits:", a);

    // Generate a random prime number of 128 bits
    BN_generate_prime_ex(a, 128, 1, NULL, NULL, NULL);
    printBN("Random prime number of 128 bits", a);

    /*BIGNUM operations*/
    // Initialize b, n, result
    BIGNUM *b = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *result = BN_new();

    BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
    BN_dec2bn(&b, "273489463796838501848592769467194369268");
    BN_rand(n, NBITS, 0, 0);

    // result = a * b
    BN_mul(result, a, b, ctx);
    printBN("a * b =", result);

    // res = a^b mod n
    BN_mod_exp(result, a, b, n, ctx);
    printBN("a^c mod n =", result);

    return 0;
}