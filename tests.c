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
    unsigned char tmp1[33], tmp2[33];
    int n = 28;

    generate_random_plaintext(n, tmp1);
    verify_plaintext(tmp1, n);
    bin2hex(tmp2, tmp1);
//    srand(3);
    printf("randomly generated string: %s\n", tmp2);

    hash(tmp2, tmp1, 1);
//    verify_plaintext(tmp2, n);
    bin2hex(tmp1, tmp2);

    printf("hashed password: %s\n", tmp1);

    reduce(n, tmp1, tmp2);
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

    reduce(n, tmp2, tmp1);
    verify_plaintext(tmp2, n);
    bin2hex(tmp1, tmp2);

    printf("reduced hash: %s\n", tmp1);

    printf("my_getrandom: %d", my_getrandom());



    return 0;
}