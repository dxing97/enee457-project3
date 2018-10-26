//
// Created by Daniel Xing on 10/15/18.
//
#include <stdio.h>
#include "project3.h"

// _GNU_SOURCE should be set before *any* includes.
// Alternatively, pass to compiler with -D, or enable GNU extensions
// with -std=gnu11 (or omit -std completely)
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>



/*
 * test a bunch of different functions in project3.h
 */
int main(int argc, char *argv[]) {
    unsigned char tmp1[33], tmp2[33], tmp3[33], tmp4[44];
    int n = 24;

    generate_random_plaintext(tmp1, n);
    verify_plaintext(tmp1, n);
    bin2hex(tmp2, tmp1);
//    srand(3);
    printf("randomly generated string: %s\n", tmp2);

    hash(tmp2, tmp1, 1);
//    verify_plaintext(tmp2, n);
    bin2hex(tmp1, tmp2);

    printf("hashed password: %s\n", tmp1);

    reduce(n, tmp1, tmp2, 0);
    verify_plaintext(tmp1, n);
    bin2hex(tmp2, tmp1);

    printf("reduced hash: %s\n", tmp2);

//    generate_random_plaintext(n, tmp1);
//    verify_plaintext(tmp1, n);
//    bin2hex(tmp2, tmp1);
//    srand(3);
//    printf("randomly generated string: %s\n", tmp2);

    hash(tmp1, tmp2, 1);
//    verify_plaintext(tmp2, n);
    bin2hex(tmp2, tmp1);

    printf("hashed password: %s\n", tmp2);

    reduce(n, tmp2, tmp1, 0);
    verify_plaintext(tmp2, n);
    bin2hex(tmp1, tmp2);

    printf("reduced hash: %s\n", tmp1);

    printf("my_getrandom: %d\n", my_getrandom());

//    struct table table;
//    table.tablelength = 1 << n/2;
//    table.entries = calloc((size_t) 1 << n/2, sizeof(struct table_entry));
//    import_table(&table, "rainbow");
//    export_table(&table, "testrainbow");
    char challengehash[] = "b8a1c2b0affbf389d6f0fc0584ccefb2";
    printf("challenge hash: %s\n", challengehash);
    hex2bin(tmp1, challengehash);
    reduce(n, tmp2, tmp1, 0);
    bin2hex(tmp3, tmp2);
    printf("reduced hash: %s\n", tmp3);
    hash(tmp1, tmp2, 1);
    bin2hex(tmp3, tmp1);
    printf("hash: %s\n", tmp3);

    reduce(n, tmp2, tmp1, 0);
    bin2hex(tmp3, tmp2);
    printf("reduced hash: %s\n", tmp3);
    hash(tmp1, tmp2, 1);
    bin2hex(tmp3, tmp1);
    printf("hash: %s\n", tmp3);

    hex2bin(tmp2, challengehash);
    new_reduce(n, tmp1, tmp2, 23);
    bin2hex(tmp3, tmp1);
    printf("new_reduce of challengehash: %s\n", tmp3);

    /*
     * all permutations are unique
     */
    int tmp;
    int offsets[1<<n/2][n/4];
    for(int i = 0; i < 1 << n/2; i++) {
        srand(i);
        for(int j = 0; j < n/4; j++) {
            tmp = rand() % 32;
            offsets[i][j] = tmp;
//            printf("%2d ", tmp);
        }
//        printf("\n");
    }

    //000000000000000000000000004F756D,0000000000000000000000000023643B chain index 1117
    //000000000000000000000000001BBBC7,00000000000000000000000000603588 chain index 1117
    //00000000000000000000000000C3A810,000000000000000000000000000FB573 chain index 1117
    hex2bin(testhash, "B8A1C2B0AFFBF389D6F0FC0584CCEFB2");
    char chainhead[33] = "00000000000000000000000000C3A810";
    char password[33] = "00000000000000000000000000A492F2";
    char chain[(1 << (n/2)) + 1][16];
    hex2bin(tmp2, password);
    hex2bin(chain[0], chainhead);
    printf("chainhead: %s\n", chainhead);
    for(int i = 0; i < 1 << n/2; i++) {
        if(hash(tmp1, chain[i], 1) == -2) {
            printf("found challenge\n");
        }
        reduce(n, chain[i+1], tmp1, i + 1);
        if(memcmp(tmp2, chain[i], 16) == 0) {
            bin2hex(tmp3, tmp1);
            printf("found challenge password at i = %d, challenge hash was %s\n", i, tmp3);
        }
    }

    char chaintail[33];
    bin2hex(chaintail, chain[(1 << n/2)]);
    printf("chaintail: %s\n", chaintail);

    bin2hex(tmp4, chain[(1 << n/2) ]);
    for (int i = 0; i < (1 << n/2); ++i) {
        reduce(n, tmp1, testhash, (1 << n/2) - i);
        for(int j = (1 << n/2) - i + 1; j <= (1 << n/2); j++) {
            hash(tmp2, tmp1, 1);
            reduce(n, tmp1, tmp2, j);
        }
        bin2hex(tmp3, tmp1);
        printf("comparing %s against %s\n", tmp3, chaintail);
        if(memcmp(tmp1, chain[(1 << n/2) ], 16) == 0) {
            printf("found plaintext in chain\n");
            return 0;
        }
    }

    return 0;
}