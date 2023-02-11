/* Task2.c
    Text to encode: "Aaron Schofield 11841499" 
    Text to Hex: 4161726F6E205363686F6669656C64203131383431343939
*/

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
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new(); // Text to encrypt
    BIGNUM *d = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    
    // Aaron Schofield 11841499
    BN_hex2bn(&M, "4161726F6E205363686F6669656C64203131383431343939");

    BIGNUM *encrypted = BN_new();
    // Encrypt = m^e mod n
    BN_mod_exp(encrypted, M, e, n, ctx);

    printBN("Encrypted message:\n\t", encrypted);

    // BIGNUM *decrypted = BN_new();
    // // Decrypted = encrypted^d mod n
    // BN_mod_exp(decrypted, encrypted, d, n, ctx);
    // printBN("Decrypted message:\n\t", decrypted);

    return 0;
}
