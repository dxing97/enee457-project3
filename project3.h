//
// Created by Daniel Xing on 10/14/18.
//

#ifndef ENEE457_PROJECT3_PROJECT3_H
#define ENEE457_PROJECT3_PROJECT3_H

#define BUF_LENGTH 16

#define USE_RAINBOW_CHAINS
//#define USE_MSB_REDUCTION
#define IGNORE_DUPLICATES
#define SEARCH_WHILE_GENERATING

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <memory.h>
#include <time.h>
//#include <sys/random.h> //cryptographically secure randomness (not that it matters too much here)
//#include <sys/syscall.h>
//#include <unistd.h>
/*
 * reduction function
 * todo: global/static EVP context to save exec time (might not be nessecary)
 */

#ifdef SEARCH_WHILE_GENERATING
char testhash[16];
#endif

struct table_entry {
    char head[16];
    char tail[16];
};

struct table {
    struct table_entry *entries;
    int tablelength;
};

int import_table(struct table *table, char *filename, int type);
int export_table(struct table *table, char *filename, int type);
int generate_table(struct table *table, int n);
int generate_chain(int n, struct table_entry *chain, int tableindex);
int search_table(struct table *table, int n, char *plaintext, char *inputhash);
int search_table_endpoints(struct table *table, int n, unsigned const char *target, int *index, int *location);
int search_chain(struct table_entry *entry, int n, char *plaintext, char *inhash);
int reduce(int n, unsigned char *out, unsigned const char *hash, int chainindex);
int new_reduce(int n, unsigned char *out, unsigned char *hash, int chainindex);
int generate_random_plaintext(unsigned char *plaintext, int n);
int verify_plaintext(unsigned const char *plaintext, int n);
int hash(unsigned char *out, unsigned char *in, int do_encrypt);
int bin2hex(char *out, char *in);
int hex2bin(char *out, char *in);
int my_getrandom();

/*
 * type 0: binary
 * type 1: ASCII-encoded hex
 */
int import_table(struct table *table, char *filename, int type) {
    char buffer[512];
    FILE *fp;
    fp = fopen(filename, "r");

    if(type == 1) {
        for(int i = 0; i < table->tablelength; i++) {

            fread(buffer, 1, 32, fp);
            hex2bin(table->entries[i].head, buffer);
//        fread(table->entries[i].head, 1, 16, fp);
            if(fgetc(fp) != ',') {
                printf("expected comma, got something else\n");
            }
            fread(buffer, 1, 32, fp);
            hex2bin(table->entries[i].tail, buffer);
//        fread(table->entries[i].tail, 1, 16, fp);
            if(fgetc(fp) != '\n') {
                printf("expected newline, got something else\n");
            }
        }
    } else if (type == 0) {
        for(int i = 0; i < table->tablelength; i++) {

//            fread(buffer, 1, 32, fp);
//            hex2bin(table->entries[i].head, buffer);
            fread(table->entries[i].head, 1, 16, fp);
            if(fgetc(fp) != ',') {
                printf("expected comma, got something else\n");
            }
//            fread(buffer, 1, 32, fp);
//            hex2bin(table->entries[i].tail, buffer);
            fread(table->entries[i].tail, 1, 16, fp);
            if(fgetc(fp) != '\n') {
                printf("expected newline, got something else\n");
            }
        }
    }


    fclose(fp);

    return 0;
}

/*
 * save rainbow table to disk
 *
 * type 0: binary
 * type 1: ASCII-encoded hex
 *
 */
int export_table(struct table *table, char *filename, int type) {
    char buffer[512];
    FILE *fp;
    fp = fopen(filename, "w");
    if(type == 1) {
        for(int i = 0; i < table->tablelength; i++) {
            bin2hex(buffer, table->entries[i].head);
            fwrite(buffer, 1, strlen(buffer), fp);
//        fwrite(table->entries[i].head, 1, 16, fp);
            fputc(',', fp);
            bin2hex(buffer, table->entries[i].tail);
            fwrite(buffer, 1, strlen(buffer), fp);
//        fwrite(table->entries[i].tail, 1, 16, fp);
            fputc('\n', fp);
        }
    } else if (type == 0) {
        for(int i = 0; i < table->tablelength; i++) {
//            bin2hex(buffer, table->entries[i].head);
//            fwrite(buffer, 1, strlen(buffer), fp);
            fwrite(table->entries[i].head, 1, 16, fp);
            fputc(',', fp);
//            bin2hex(buffer, table->entries[i].tail);
//            fwrite(buffer, 1, strlen(buffer), fp);
            fwrite(table->entries[i].tail, 1, 16, fp);
            fputc('\n', fp);
        }
    }


    fclose(fp);

    return 0;
}

int generate_table(struct table *table, int n) {
    srand((unsigned int) (my_getrandom() + time(NULL)));
    char tmp[33];

    int hashcount = 0, ret;
    struct table_entry *new_entry;
    table->tablelength = 0;
    table->entries = calloc((size_t) (1 << n/2), sizeof(struct table_entry)); //allocate all entries up front
    if(table->entries == NULL) {
        printf("error allocating entries while generating table\n");
        return -1;
    }

    while(table->tablelength < (1 << n/2)) {
        hashcount = generate_chain(n,
                                   &(table->entries[table->tablelength]), table->tablelength);
        if(hashcount == -1) {
            printf("generate_table: error generating new chain while generating table\n");
            return -1;
        }
//        bin2hex(tmp, table->entries[table->tablelength].head);
//        printf("head: %s\n", tmp);
        table->tablelength++;
        if(table->tablelength % 4 == 0) {
            printf("\rgenerate_table: progress %2.4f%%", (float) 100 * table->tablelength / (float) (1 << n/2));
            fflush(stdout);
        }
    }

    return hashcount;
}

int generate_chain(int n, struct table_entry *chain, int tableindex) {
    int hashcount = -1, chainlength = 0;
    int found;
    int repeated = 0, location;
    unsigned char head[16], current[16], current_hash[16], tail[16];
    unsigned char tmp[33], tmp1[33];


    generate_random_plaintext(current, n);
//    hex2bin(current, "00000000000000000000000000C3A810");
    memcpy(chain->head, current, 16);

    bin2hex(tmp1, current);
//    printf("hede: %s\n", tmp);

    verify_plaintext(current, n);

    while(chainlength < (1 << n/2)) {
//        no point checking for collisions
//        found = search_table_endpoints(table, n, current, NULL, NULL);
        hashcount = hash(current_hash, current, 1);
#ifdef SEARCH_WHILE_GENERATING
        if(hashcount == -2) {
            bin2hex(tmp, current);
            printf("table index: %d, chain index: %d chain head: %s plaintext: %s\n",tableindex, chainlength, tmp1, tmp);
        }
#endif
#ifndef USE_RAINBOW_CHAINS
        reduce(n, current, current_hash, 0);
#else
        reduce(n, current, current_hash, chainlength + 1);
#endif
//                bin2hex(tmp, current);
//                printf("plaintext: %s\n", tmp);

        chainlength++;

    }
//    tail = current;
//    bin2hex(tmp, current);
//    printf("tail: %s\n", tmp);
//    if(repeated == 1)
//        printf("repeated at chainlength %d", location);
//    memcpy(chain->head, head, 16);
    memcpy(chain->tail, current, 16);
#ifndef IGNORE_DUPLICATES
    found = search_table_endpoints(table, n, chain->tail, NULL, NULL);
    if(found == 2) {
        //collision at tail, should redo
        generate_chain(table, n, chain);
    }
#endif

    return hashcount;
}

/*
 * given a hash, search through the rainbow table.
 *
 * if the plaintext hash of the password is found, save the plaintext in "plaintext" and return 0
 * otherwise, do not touch "plaintext" and return 1
 */
int search_table(struct table *table, int n, char *plaintext, char *inputhash) {
    int i, j, index, loc;
    unsigned char current_hash[16], current_plaintext[16], final_plaintext[16], tmp[33];
    memcpy(current_hash, inputhash, 16);

    for(i = 0; i < (1 << n/2); i++) {
#ifndef USE_RAINBOW_CHAINS
        reduce(n, current_plaintext, current_hash, 0);
#else
        reduce(n, current_plaintext, inputhash, (1 << n/2) - i);
        for(j = (1 << n/2) - i + 1; j <= (1 << n/2); j++){
            hash(current_hash, current_plaintext, 1);
            reduce(n, current_plaintext, current_hash, j);
        }
#endif
        bin2hex(tmp, current_plaintext);
//        printf("searching for %s\n", tmp);
        j = search_table_endpoints(table, n, current_plaintext, &index, &loc);
        switch(j) {
            case 2: //found at tail
                //search the chain
#ifndef USE_RAINBOW_CHAINS
                printf("search_table: plaintext %s at chain index %d matches tail at %d, searching chain\n", tmp, i, index);
#else
                printf("search_table: plaintext %s at chain index %d matches tail at %d, searching chain\n", tmp, (1 << n/2) - i - 1, index);
#endif
                if(!search_chain(&(table->entries[i]), n, final_plaintext, inputhash)) {
                    printf("search_table: found password from chain at table index %d\n", i);
                    memcpy(plaintext, final_plaintext, 16);
                    return 0;
                }
                break;
            case 1:
                printf("search_table: plaintext %s at chain index %d matches head at %d, ignoring\n", tmp, i, index);
                break;
            case 0:
            default:
                break;
        }
#ifndef USE_RAINBOW_CHAINS
        hash(current_hash, current_plaintext, 1);
#endif
    }
    return 1;
}

/*
 * given a plaintext, find if it's already in the table's endpoints (head/tail)
 * return values:
 * 0 - not found in table
 * 1 - found in head
 * 2 - found in tail
 * index: if pointer is not null, sets it to index in table
 * location: if pointer is not null, sets is to 0 (head) or 1 (tail)
 */
int search_table_endpoints(struct table *table, int n, unsigned const char *target, int *index, int *location) {
    char tmp1[33], tmp2[33];
    bin2hex(tmp2, target);

    for(int i = 0; i < table->tablelength; i++) {
        if(memcmp(target, table->entries[i].head, 128/8) == 0){
//            bin2hex(tmp1, table->entries[i].head);
//            printf("found duplicate of %s in %s at entry %d head\n", tmp2, tmp1, i);
//            printf("repeat at head pos %d", i);
            if(index != NULL) {
                *index = i;
            }
            if(location != NULL) {
                *location = 0;
            }
            return 1;
        }
        if(memcmp(target, table->entries[i].tail, 128/8) == 0) {
//            bin2hex(tmp1, table->entries[i].head);
//            printf("found duplicate of %s in %s at entry %d tail\n", tmp2, tmp1, i);
//            printf("repeat at tail pos %d", i);
            if(index != NULL) {
                *index = i;
            }
            if(location != NULL) {
                *location = 0;
            }
            return 2;
        }
    }
    return 0;
}

/*
 * given a hash and a table entry, find the plaintext that hashes to the target hash
 * returns 0 if a sucessful match was found
 * returns 1 if nothing was found
 */
int search_chain(struct table_entry *entry, int n, char *plaintext, char *inhash) {
    char currenthash[16], currentplaintext[16];

    memcpy(currentplaintext, entry->head, 16);
    hash(currenthash, entry->head, 1);

    for(int i = 0; i < 1 << n/2; i++) {
        if(memcmp(currenthash, inhash, 16) == 0) {//matching hash
            printf("found at chain position %d", i);
            memcpy(plaintext, currentplaintext, 16);
            return 0;
        }
#ifndef USE_RAINBOW_CHAINS
        reduce(n, currentplaintext, currenthash, 0);
#else
        reduce(n, currentplaintext, currenthash, i + 1);
#endif
        hash(currenthash, currentplaintext, 1);

    }
    printf("search_chain: did not find matching hash in chain\n");
    return 1;
}
/*
 * take the input hash and reduce it back into the password space
 * todo: add position-based reduction
 */
int reduce(int n, unsigned char *out, unsigned const char *hash, int chainindex) {
    //naive approach: mod by 2^n
    if(chainindex == 0) {
        memset(out, 0, 16);
#ifndef USE_MSB_REDUCTION
        for(int i = 0; i < 16 ; i++) {
            if (i < 16 - n / 8 - 1) {
                out[i] = 0;
            } else if (((n/4) % 2 == 1) && (i == 16-n/8 - 1)) {
                out[i] = hash[i] & (unsigned char) 0x0F;
            } else if ((n/4)%2 == 0 && (i == 16-n/8-1)) {
                out[i] = 0;
            } else {
                out[i] = hash[i];
            }
        }
//        for (int i = 0; i < 16; i++) {
//            if (i < 16 - n / 8) {
//                out[i] = 0;
//            } else if ((n / 4 % 2 == 1) && (i == 16 - n / 8)) {
//                out[i] = hash[i] & (unsigned char) 0x0F;
//            } else {
//                out[i] = hash[i];
//
//            }
//        }
#else
        for (int i = 0; i < 16; i++) {
            if (i < 16 - n / 8) {
                out[i] = 0;
            } else if ((n / 4 % 2 == 1) && (i == 16 - n / 8)) {
                out[i] = hash[16-i] & (unsigned char) 0x0F;
            } else {
                out[i] = hash[16-i];

            }
        }
#endif
        if (verify_plaintext(out, n)) {
            printf("error with reduction function\n");
            return 2;
        }
//        char tmp[33];
//        bin2hex(tmp, out);
//        printf("(%d) reduction: %s\n",n,  tmp);
        return 0;
    } else {
        new_reduce(n, out, hash, chainindex);
    }
}

int offset_is_duplicate(int offsets[], int len, int cp) {
    for(int i = 0; i < len; i++) {
        if(offsets[i] == cp) {
            return 1;
        }
    }
    return 0;
}
/*
 * chainindex: position in the rainbow chain we're reducing this hash for, starts at 1 and ends at 1 << n/2 (add one)
 * unique (hopefully) reduction function at every position in the chain
 */
int new_reduce(int n, unsigned char *out, unsigned char *hash, int chainindex) {
    if(chainindex > (1 << n/2)) {
        printf("new_reduce: chainindex (%d) is greater than 2^n/2 - 1 (%d)\n", chainindex, (1 << n/2) - 1);
        return 1;
    }

    int cp = 0, o, tmp; //current position and offset in half-bytes (4 bits)
//    printf("chainindex: %d\n", chainindex);

    srand((unsigned) chainindex); //srand(0) is the same as srand(1)
    unsigned char extracts[n/4];
    int offsets[n/4];
    char tmp1[33];

    for(int i = 0; i < n/4; i++) {
        cp = (rand() % 32);
        while(offset_is_duplicate(offsets, i, cp) == 1) {
            cp = (rand() % 32);
        }
//        cp = (cp + o) % 32;
//        printf("%02d,", cp);
        offsets[i] = cp;

        if(cp % 2 == 1) { //extracting LSBs
            extracts[i] = hash[cp/2] & (unsigned char) 0x0F;
        } else { //extracting MSBs
            extracts[i] = hash[cp/2] >> 4;
        }
//        printf(("(%X),"), extracts[i]);
    }
//    printf("\n");
    int remainingextracts = n/4;
    for(int i = 0; i < 16 ; i++) {
        if (i < 16 - n / 8 - 1) {
            out[i] = 0;
        } else if (((n/4) % 2 == 1) && (i == 16-n/8 - 1)) {
            out[i] = (unsigned char) extracts[n / 4 - remainingextracts] & (unsigned char) 0x0F;
            remainingextracts--;
        } else if ((n/4)%2 == 0 && (i == 16-n/8-1)) {
            out[i] = 0;
        } else {
            out[i] = (extracts[n/4 - remainingextracts] << 4) | extracts[n/4 - remainingextracts + 1];
            remainingextracts -= 2;
        }
    }
    if(remainingextracts != 0) {
        printf("remainingextracts != 0 (%d\n", remainingextracts);
    }
    if(verify_plaintext(out, n) != 0) {
        bin2hex(tmp1, out);
        printf("new_reduce: generated invalid plaintext (%s for n = %d)\n", tmp1, n);
        return 1;
    }
    return 0;
}


/*
 * generate a BUF_LENGTH bit char array that satisfies the
 * requirements for the password
 */
int generate_random_plaintext(unsigned char *plaintext, int n) {
    srand(my_getrandom());

    for(int i = 0; i < 16 ; i++) {
        if (i < 16 - n / 8 - 1) {
            plaintext[i] = 0;
        } else if (((n/4) % 2 == 1) && (i == 16-n/8 - 1)) {
            plaintext[i] = (unsigned char) rand() & (unsigned char) 0x0F;
        } else if ((n/4)%2 == 0 && (i == 16-n/8-1)) {
            plaintext[i] = 0;
        } else {
            plaintext[i] = (unsigned char) rand() & (unsigned char) 0xFF;
        }
    }
//    for(int i = 0; i < 16 ; i++) {
//        if (i < 16 - n / 8) {
//            plaintext[i] = 0;
//        } else if ((n/4 % 2 == 1) && (i == 16-n/8)) {
//            plaintext[i] = (unsigned char) rand() & (unsigned char) 0x0F;
//        } else {
//            plaintext[i] = (unsigned char) rand();
//
//        }
//    }
    if(verify_plaintext(plaintext, n) != 0){
        printf("generate_random_plaintext: generated invalid plaintext\n");
    }
    return 0;
}

/*
 * returns 0 if the plaintext is valid, 1 if not valid
 * the first 128-n bits of plaintext must be 0
 */
int verify_plaintext(unsigned const char *plaintext, int n) {
    int res;
    if(n == 128) {
        return 0;
    }
    for(int i = 0; i < 16-n/8; i++) {
        if(plaintext[i] != 0 && (n/4)%2 != 1){
            printf("verify_plaintext: invalid plaintext: %dth byte is nonzero\n", i);
            return 1;
        }
    }
//    int diff = n - (n/8)*8;
    if(n/4%2 == 1) {
        res = plaintext[16 - n/8 - 1] & 0xF0;
        if(res != 0){
            printf("verify_plaintext: invalid plaintext: most signinificant half of %dth byte(= %d) is nonzero (res = %d)\n", 16-n/8, plaintext[16-n/8 - 1], res);
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
 * do_encrypt:
 *  1 - encrypt
 *  0 - decrypt
 *  -1 - do nothing
 */
int hash(unsigned char *out, unsigned char *in, int do_encrypt) {
    static int hashcount = 0; //project requirement
    if(do_encrypt == -1) {
        return hashcount;
    }
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

#ifdef SEARCH_WHILE_GENERATING
    if(memcmp(out, testhash, 16) == 0) {
        printf("\nfound matching hash with testhash\n");
        return -2;
    }
#endif

    hashcount++;
    return hashcount;
}

/*
 * convert the 16 byte char/binary array into a 33 byte ASCII hex string
 */
int bin2hex(char *out, char *in) {
    int i;
    for(i = 0; i < 32; i++) {
//        out[i] = (i % 2 ? in[i/2] >> 4 : in[i/2] & (char) 0x0F);
        unsigned char tmp = (unsigned char) (i % 2 ? in[i/2] & 0x0F : (in[i/2] >> 4) & 0x0F );
        sprintf(&out[i], "%X", tmp);
//        unsigned char tmp = (unsigned char) (i % 2 ? in[i/2] & 0b00001111 : in[i/2] >> 4 );
//        printf("%X", tmp);
    }
    out[32] = '\0';
    return 0;
}

int hex2bin(char *out, char *in) {
    int i;
    memset(out, 0, 16);
    unsigned long k;
    if(strlen(in) != BUF_LENGTH*2) {
        printf("hex2bin: ASCII hex string has incorrect length (%d)", (int) (strlen(in)));
        return 1;
    }

    for (int j = 0; j < 32; j++) {
        k = (unsigned) strtol( (char[]) {in[j], 0}, NULL, 16);
//        printf("{%c%X",in[j], k);
        out[j/2] = (unsigned char) ((j % 2) ? (k + out[j/2]) : (k << 4)); //if even or odd...
//        if(j % 2 == 1) {
//            printf("%X}", (unsigned char) out[j/2]);
//        }
    }

    return 0;
}

int my_getrandom()
{
    int bytes = 4; //int
    char buf[bytes];
    int ret = 0;
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    if(fp == NULL) {
        printf("could not open /dev/urandom for reading");
        return 1;
    }
    fread(buf, 1, (size_t) bytes, fp);
    for(int i = bytes - 1; i >= 0; i--) {
        ret = ret + (buf[bytes - 1 - i] << i*8);
    }

    fclose(fp);
    return ret;
}

#endif //ENEE457_PROJECT3_PROJECT3_H
