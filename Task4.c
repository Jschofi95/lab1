/* Task4.c */

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

    BIGNUM *n = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *f = BN_new();
    BIGNUM *d = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&c, "4161726F6E205363686F6669656C64206F776520796F75202432303030"); // Aaron Schofield owe you $2000
    BN_hex2bn(&f, "4161726F6E205363686F6669656C64206F776520796F75202433303030"); // Aaron Schofield owe you $3000

    BIGNUM *encrypted = BN_new();
    // Decrypted = encrypted^d mod n
    BN_mod_exp(encrypted, c, d, n, ctx);
    printBN("$2000:\n\t", encrypted);

    BN_mod_exp(encrypted, f, d, n, ctx);
    printBN("$3000:\n\t", encrypted);

    return 0;
}