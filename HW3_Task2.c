#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n",msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *ciphertext = BN_new();
    BIGNUM *plaintext = BN_new();

    // Initialize n,M,e,d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m, "4120746f702073656372657421");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    //Generate ciphertext, C = M^e mod n where m is plaintext, e is encryption key and n is p*q 
    BN_mod_exp(ciphertext,m,e,n,ctx);
    printBN("Ciphertext = ", ciphertext);
    //Use d to decrypt and find m and then compare original M with computed m
    BN_mod_exp(plaintext,ciphertext,d,n,ctx);
    printBN("Computed plaintext = ", plaintext);
    printBN("Original plaintext = ", m);
    //check if plaintext is the same
    if (BN_cmp(plaintext,m)==0)
    {
        printf("Plaintext Matched. Task Completed!");
    }
    return 0;
}