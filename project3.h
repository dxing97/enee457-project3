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
int search_table(struct table *table, int n, char *plaintext, char *hash);
int search_table_endpoints(struct table *table, int n, unsigned const char *target);
int reduce(int n, unsigned char *out, unsigned const char *hash);
int generate_random_plaintext(int n, unsigned char *plaintext);
int verify_plaintext(unsigned const char *plaintext, int n);
int hash(unsigned char *out, unsigned char *in, int do_encrypt);
int bin2hex(char *out, char *in);
int hex2bin(char *out, char *in);

int import_table(struct table *table, char *filename) {

    return 0;
}

/*
 * save rainbow table to disk
 */
int export_table(struct table *table, char *filename) {
    char buffer[512];
    FILE *fp;
    fp = fopen(filename, "w");

    for(int i = 0; i < table->tablelength; i++) {
//        bin2hex(buffer, table->entries[i].head);
//        fwrite(buffer, 1, strlen(buffer), fp);
        fwrite(table->entries[i].head, 1, 16, fp);
        fputc(',', fp);
//        bin2hex(buffer, table->entries[i].tail);
//        fwrite(buffer, 1, strlen(buffer), fp);
        fwrite(table->entries[i].tail, 1, 16, fp);
        fputc('\n', fp);
    }

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
    unsigned char tmp[33];

    generate_random_plaintext(n, current);
    memcpy(head, current, 16);

    bin2hex(tmp, head);
//    printf("head: %s\n", tmp);

    while(chainlength < (1 <<n /2)) {
//        printf("chainlength: %d\n", chainlength);
        found = search_table_endpoints(table, n, current);
        switch(found) {
            case 1:
            case 2:
//                generate_random_plaintext(n, current);
//                strcpy(head, current);
//                chainlength = 0;
//                break;
//                printf("found repeated element in table");
                if(repeated == 0)
                    location = chainlength;
                bin2hex(tmp, current);
//                printf("repeated: %s\n", tmp);
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
//    tail = current;

    bin2hex(tmp, current);
//    printf("tail: %s\n", tmp);
    if(repeated == 1)
        printf("repeated at chainlength %d", location);
    memcpy(chain->head, head, 16);
    memcpy(chain->tail, current, 16);

    return hashcount;
}

/*
 * given a hash, search through the rainbow table.
 *
 * if the plaintext hash of the password is found, save the plaintext in "plaintext" and return 0
 * otherwise, do not touch "plaintext" and return 1
 */
int search_table(struct table *table, int n, char *plaintext, char *hash) {

    return 0;
}

/*
 * given a plaintext, find if it's already in the table's endpoints (head/tail)
 * return values:
 * 0 - not found in table
 * 1 - found in head
 * 2 - found in tail
 */
int search_table_endpoints(struct table *table, int n, unsigned const char *target) {
    char tmp1[33], tmp2[33];
    bin2hex(tmp2, target);

    for(int i = 0; i < table->tablelength; i++) {
        if(memcmp(target, table->entries[i].head, 128/8) == 0){
//            bin2hex(tmp1, table->entries[i].head);
//            printf("found duplicate of %s in %s at entry %d head\n", tmp2, tmp1, i);
            printf("repeat at head pos %d", i);
            return 1;
        }
        if(memcmp(target, table->entries[i].tail, 128/8) == 0) {
//            bin2hex(tmp1, table->entries[i].head);
//            printf("found duplicate of %s in %s at entry %d tail\n", tmp2, tmp1, i);
            printf("repeat at tail pos %d", i);
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
int verify_plaintext(unsigned const char *plaintext, int n) {
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
 * in: key for AES-128
 * out: encrypted AES-128 string
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
// there are no partials here that we need to worry about
//    printf("result length plaintext bytes: %d\n", outlen);
//
//    if (!EVP_CipherFinal_ex(ctx, out, &outlen)) {
//        /* Error */
//        EVP_CIPHER_CTX_free(ctx);
//        return 0;
//    }

//    printf("result length plaintext bytes: %d\n", outlen);

    EVP_CIPHER_CTX_free(ctx);

    hashcount++;
    return hashcount;
}

/*
 * convert the 16 byte char array into a 33 byte ASCII hex array
 */
int bin2hex(char *out, char *in) {
    int i;
    for(i = 0; i < 32; i++) {
//        out[i] = (i % 2 ? in[i/2] >> 4 : in[i/2] & (char) 0x0F);
        sprintf(&out[i], "%X", (i % 2 ? in[i/2] & (char) 0x0F : in[i/2] >> 4 ));
    }
    out[32] = '\0';
    return 0;
}

int hex2bin(char *out, char *in) {
    int i;
    long k;
    if(strlen(in) != BUF_LENGTH*2) {
        printf("hex2bin: ASCII hex string has incorrect length (%d)", (int) (strlen(in)));
        return 1;
    }

    for (int j = 0; j < 32; j++) {
        k = strtol( (char[]) {in[j], 0}, NULL, 16);
        out[j/2] = (char) ((j % 2) ? (k) : (k << 4)); //if even or odd...
    }

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
