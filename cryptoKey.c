#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int encrypt(unsigned char* in, unsigned char* charout, unsigned char* key, unsigned char* iv);

int main() {
    // Retrieve world File
    FILE *word_file = fopen("words.txt", "r");

    // Set character arrays used
    unsigned char plaintext[] = "This is a top secret.";
    unsigned char iv[] =  {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99, 0x88, 0x77,
                              0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    unsigned char ciphertext[] = {0x76, 0x4a, 0xa2, 0x6b, 0x55, 0xa4, 0xda, 0x65, 0x4d, 0xf6, 0xb1,
                                    0x9e, 0x4b, 0xce, 0x00, 0xf4, 0xed, 0x05, 0xe0, 0x93, 0x46, 0xfb,
                                    0x0e, 0x76, 0x25, 0x83, 0xcb, 0x7d, 0xa2, 0xac, 0x93, 0xa2};

    // Grab the words from a file     
    unsigned char key[1024];
    while((fgets(key, 1024, word_file)) != NULL) { // Grab from line by line
        // Add the padding
        for(int i = 0; i <  16; i++) { 
             if(key[i] == '\n') {
                 for(int j = i; j < 16; j++) {
                     key[j] = '#';
                 }
                 key[16] = '\0';
             };
        }

        // Pass values to encrypt function, returns 1 if true
        int answer = encrypt(plaintext, ciphertext, key, iv);

        // If 1, stop loop and display key
        if(answer == 1) {
            printf("The key is: %s\n", key);
            break;
        }
    }

    fclose(word_file);
    return 0;
}

int encrypt(unsigned char* in, unsigned char* charout, unsigned char* key, unsigned char* iv) {
    // Allow enough space in the output for additional block
    unsigned char outputBuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inputLen, outputLen, tempLen;

    // Create and initialize new cipher context
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    // Set the key and IV
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    // Run the encryption
    if(!EVP_EncryptUpdate(ctx, outputBuf, &outputLen, in, strlen(in))) {
        EVP_CIPHER_CTX_free(ctx);
        printf("There was an error in update\n");
        return 0;
    }

    // Finalize Encryption
    if(!EVP_EncryptFinal_ex(ctx, outputBuf + outputLen, &tempLen)) {
        EVP_CIPHER_CTX_free(ctx);
        printf("There was an error in final\n");
        return 0;
    }

    // Compare expected result with the actual result
    // return 1 if true
    if(memcmp(outputBuf, charout, 32) == 0) {
        EVP_CIPHER_CTX_free(ctx);
        printf("THE KEY WORKS!\n");
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}