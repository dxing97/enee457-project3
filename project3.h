//
// Created by Daniel Xing on 10/14/18.
//

#ifndef ENEE457_PROJECT3_PROJECT3_H
#define ENEE457_PROJECT3_PROJECT3_H

#define BUF_LENGTH 16

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <memory.h>

/*
 * reduction function
 * todo: global/static EVP context to save exec time (might not be nessecary)
 */


struct table_entry {
    char head[16];
    char tail[16];
};

struct table {
    struct table_entry *entries;
    int tablelength;
};

int import_table();
int export_table();
int generate_table(struct table *table, int n);
int generate_chain(struct table *table, int n, struct table_entry *chain);
int search_table(struct table *table, int n, unsigned const char *target);
int reduce(int n, unsigned char *out, unsigned const char *hash);
int generate_random_plaintext(int n, unsigned char *plaintext);
int hash(unsigned char *out, unsigned char *in, int do_encrypt);


/*
 * returns 0 if the plaintext is valid, 1 if not valid
 * the first 128-n bits of plaintext must be 0
 */
int verify_plaintext(unsigned char *plaintext, int n) ;

int import_table() {
    return 0;
}

int export_table(struct table *table, char *filename) {
    return 0;
}

int generate_table(struct table *table, int n) {
    int hashcount = 0, ret;
    struct table_entry *new_entry;
    table->tablelength = 0;
    table->entries = calloc((size_t) (1 << n/2), sizeof(struct table_entry)); //allocate all entries up front
    if(table->entries == NULL) {
        printf("error allocating entries while generating table\n");
        return -1;
    }

    while(table->tablelength < (1 << n/2)) {
        hashcount = generate_chain(table, n,
                &(table->entries[table->tablelength]));
        if(hashcount == -1) {
            printf("error generating new chain while generating table");
            return -1;
        }
        table->tablelength++;
        if(table->tablelength % 128 == 0)
            printf("tablelength: %d\n", table->tablelength);
    }

    return hashcount;
}

int generate_chain(struct table *table, int n, struct table_entry *chain) {
    int hashcount = -1, chainlength = 0;
    int found;
    int repeated = 0, location;
    unsigned char head[16], current[16], current_hash[16], tail[16];

    generate_random_plaintext(n, current);
    strcpy(head, current);

    while(chainlength < (1 <<n /2)) {
//        printf("chainlength: %d\n", chainlength);
        found = search_table(table, n, current);
        switch(found) {
            case 1:
//                break;

            case 2:
//                generate_random_plaintext(n, current);
//                strcpy(head, current);
//                chainlength = 0;
//                break;
//                printf("found repeated element in table");
                if(repeated == 0)
                    location = chainlength;
                repeated = 1;
            case 0:
                hashcount = hash(current_hash, current, 1);
                reduce(n, current, current_hash);
                chainlength++;
                break;

            default:
                return -1;
//                break;
        }
    }
    if(repeated == 1)
        printf("repeated at chainlength %d", location);
    strncpy(chain->head, head, 16);
    strncpy(chain->tail, tail, 16);

    return hashcount;
}

/*
 * given a plaintext, find if it's already in the table.
 * return values:
 * 0 - not found in table
 * 1 - found in head
 * 2 - found in tail
 */
int search_table(struct table *table, int n, unsigned const char *target) {
    for(int i = 0; i < table->tablelength; i++) {
        if(strncmp(target, table->entries[i].head, 128/8) == 0){
//            printf("repeat at head pos %d", i);
            return 1;
        }
        if(strncmp(target, table->entries[i].tail, 128/8) == 0) {
//            printf("repeat at tail pos %d", i);
            return 2;
        }
    }
    return 0;
}

/*
 * take the input hash and reduce it back into the password space
 * todo: fix problem here
 */
int reduce(int n, unsigned char *out, unsigned const char *hash) {
    //naive approach: mod by 2^n
    memset(out, 0, 16);

    for(int i = 16-n/8-1; i < 16; i++) {
        out[i] = hash[i];
    }

    int diff = n - (n/8)*8;
    if(diff) {
        out[15-n/8] = hash[15-n/8] & (((1 << diff) - 1));
//        int res = hash[15 - n/8] & ~((1 << (diff)) - 1);
//        if(res != 0){
//            printf("invalid plaintext found!\n");
//            return 1;
//        }

    }

    if(verify_plaintext(out, n)){
        printf("error with reduction function\n");
        return 2;
    }
    return 0;
}


/*
 * generate a BUF_LENGTH bit char array that satisfies the
 * requirements for the password
 */
int generate_random_plaintext(int n, unsigned char *plaintext) {
    for(int i = 0; i < 16 ; i++) {
        if (i < 16 - n / 8 - 1) {
            plaintext[i] = 0;
        } else {
            plaintext[i] = (unsigned char) rand();

        }
        if((n/8)*8 != n) {
            plaintext[16-n/8 - 1] %= 0x10;
        }
    }
    if(verify_plaintext(plaintext, n) != 0){
        printf("error with random gen function\n");
    }
    return 0;
}

/*
 * returns 0 if the plaintext is valid, 1 if not valid
 * the first 128-n bits of plaintext must be 0
 */
int verify_plaintext(unsigned char *plaintext, int n) {
    int tmp;
    if(n == 128) {
        return 0;
    }
    for(int i = 0; i < 16-n/8-1; i++) {
        if(plaintext[i] != 0){
            printf("invalid plaintext found!\n");
            return 1;
        }
    }
    int diff = n - (n/8)*8;
    if((n/8)*8 != n) {
        int res = plaintext[15 - n/8] & ~((1 << (diff)) - 1);
        if(res != 0){
            printf("invalid plaintext found!\n");
            return 1;
        }

    }
    return 0;
}

/*
 * given an input string, encrypt/decrypt it and save it to the output
 * string. string lengths are fixed length.
 */
int hash(unsigned char *out, unsigned char *in, int do_encrypt) {
    static int hashcount = 0; //project requirement
    unsigned char plaintext[16];
    memset(&plaintext, 0, 16);
    int outlen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    //use ecb for no IV/chaining
    EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);

    EVP_CipherInit_ex(ctx, NULL, NULL, in, NULL , do_encrypt);

    /* perform the encryption */
    if (!EVP_CipherUpdate(ctx, out, &outlen, plaintext, BUF_LENGTH)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (!EVP_CipherFinal_ex(ctx, out, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

//    printf("result length plaintext bytes: %d\n", outlen);

    EVP_CIPHER_CTX_free(ctx);

    hashcount++;
    return hashcount;
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
