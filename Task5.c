/* Task5.c */

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
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *M = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();

    BN_hex2bn(&M, "4C61756E63682061206D697373696C652E"); // Launch a missile.
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"); // Alice's signature
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    BN_mod_exp(res, S, e, n, ctx); // Encrypt message using Alice's signature

    if (BN_cmp(res, M) == 0){
        printf("Valid\n");
    } else {
        printf("Not valid\n");
    }

    return 0;
}
