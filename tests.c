//
// Created by Daniel Xing on 10/15/18.
//
#include <stdio.h>
#include "project3.h"


/*
 * test a bunch of different functions in project3.h
 */
int main(int argc, char *argv[]) {
    unsigned char tmp1[33], tmp2[33];
    int n = 28;

    generate_random_plaintext(n, tmp1);
    verify_plaintext(tmp1, n);
    str2hex(tmp2, tmp1);

    printf("randomly generated string: %s\n", tmp2);

    hash(tmp2, tmp1, 1);
//    verify_plaintext(tmp2, n);
    str2hex(tmp1, tmp2);

    printf("hashed password: %s\n", tmp1);

    reduce(n, tmp1, tmp2);
    verify_plaintext(tmp1, n);
    str2hex(tmp2, tmp1);

    printf("reduced hash: %s", tmp2);



    return 0;
}