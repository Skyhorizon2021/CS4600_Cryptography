#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

int aesencrypt(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key,unsigned char* iv);
int main () {
        /* Allow enough space in output buffer for additional block */
        unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen, templen;
        EVP_CIPHER_CTX *ctx;
        /* Bogus key and IV: we'd normally set these from
         * another source.
         */
	unsigned char plaintext [] ="This is a top secret.";
        unsigned char key [1024];
        unsigned char iv [] ={0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
	unsigned char ciphertext []= {0x76,0x4a,0xa2,0x6b,0x55,0xa4,0xda,0x65,0x4d,0xf6,0xb1,0x9e,0x4b,0xce,0x00,0xf4,0xed,0x05,0xe0,0x93,0x46,0xfb,0x0e,0x76,0x25,0x83,0xcb,0x7d,0xa2,0xac,0x93,0xa2};

        //open the file with list of passwords
        FILE *wordptr;
        wordptr=fopen("words.txt", "r");
        //exit program if file can't be opened
        if (wordptr ==NULL) {
                perror("Unable to open the file");
                exit(1);
        }
        
        //create a buffer to hold individual line from the word list
        while (fgets(key, 1024, wordptr) ) {
                //padding
                for(int i =0;i<16;i++) {
                        if(key[i] == '\n'){
                                for(int j=i;j<16;j++) {
                                        key[j] = '#';
                                }
                                key[16]='\0';
                        }
                }
                //pass mod password to encrypt, and return 1 if matched
                int pwdVal = aesencrypt(plaintext,ciphertext,key,iv);

                //if matched, break loop and print the correct key
                if(pwdVal==1){
                        printf("The correct key is %s\n",key);
                        break;
                }
        
        }
        fclose(wordptr);
        return 0;
}
int aesencrypt(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key,unsigned char* iv) {
        //initialize var for memory
        unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int inlen, outlen, templen;
        EVP_CIPHER_CTX *ctx;
        ctx = EVP_CIPHER_CTX_new();

        //Set key and IV
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

        //Encryption
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, strlen(plaintext))) {
         /* Error */
                EVP_CIPHER_CTX_free(ctx);
                printf("Error in updating encryption\n");
                return 0;
     	}
	if (!EVP_EncryptFinal_ex(ctx, outbuf+outlen, &templen)) {
         /* Error */
                EVP_CIPHER_CTX_free(ctx);
                printf("Error in final encryption\n");
                return 0;
     	}
	
        //Compare computed ciphertext with expected ciphertext
	if (memcmp(outbuf, ciphertext, 32) == 0){
                EVP_CIPHER_CTX_free(ctx);
                printf("Ciphertext matched!\n");
                return 1;
        }
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
}
