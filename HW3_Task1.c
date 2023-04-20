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
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *val = BN_new();

    // Initialize p, q, e, val
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_hex2bn(&val, "1");
    
    // p-1,q-1,
    BN_sub(p,p,val);
    printBN("p-1 = ",p);
    BN_sub(q,q,val);
    printBN("q-1 = ",q);
    // phi = (p-1)*(q-1)
    BN_mul(phi, p, q, ctx);
    printBN("Phi(n) = ", phi);
    // d = (e^(-1)) mod phi(n)
    BN_mod_inverse(d, e,phi, ctx);
    printBN("d = ", d);
    return 0;
    
}

