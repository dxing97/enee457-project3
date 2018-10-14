//
// Created by Daniel Xing on 10/14/18.
//

#ifndef ENEE457_PROJECT3_PROJECT3_H
#define ENEE457_PROJECT3_PROJECT3_H

#define BUF_LENGTH 16

#include <openssl/ssl.h>
#include <openssl/evp.h>

/*
 * given an input string, encrypt/decrypt it and save it to the output string. string lengths are fixed length.
 */
int do_encrypt_string(char *in, char *out, unsigned char *key, int do_encrypt) {
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
//    unsigned char key[] = "0123456789abcdef";
    unsigned char iv[17];
    memset(&iv, 0, 17);

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL,
                      do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
//    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    if (!EVP_CipherUpdate(ctx, out, BUF_LENGTH, in, BUF_LENGTH)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

//    for (;;) {
//        inlen = (int) fread(inbuf, 1, 1024, in);
//        if (inlen <= 0)
//            break;
//        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
//            /* Error */
//            EVP_CIPHER_CTX_free(ctx);
//            return 0;
//        }
//        fwrite(outbuf, 1, (size_t) outlen, out);
//    }
    if (!EVP_CipherFinal_ex(ctx, out, BUF_LENGTH)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
//    fwrite(outbuf, 1, (size_t) outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "0123456789abcdEf";
    unsigned char iv[] = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                      do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    for (;;) {
        inlen = (int) fread(inbuf, 1, 1024, in);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, (size_t) outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, (size_t) outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

#endif //ENEE457_PROJECT3_PROJECT3_H
