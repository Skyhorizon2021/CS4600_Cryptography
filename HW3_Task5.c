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
    BIGNUM *plaintext = BN_new();
    BIGNUM *signature = BN_new();


    // Initialize n, M, e, signature
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&signature, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    //Verify signature using sig^e mod n = m. If not equal, false signature
    BN_mod_exp(plaintext,signature,e,n,ctx);
    printBN("Computed plaintext = ",plaintext);
    printBN("Original plaintext = ",m);

    //check if plaintext is the same
    if (BN_cmp(plaintext,m)==0)
    {
        printf("Plaintext Matched. Signature Verified!");
    } 
    else
    {
        printf("Plaintext Not Matched. Invalid Signature!");
    }
    return 0;
}