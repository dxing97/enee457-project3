//
// Created by Daniel Xing on 10/24/18.
//

#include "project3.h"


/*
 * arguments:
 * bruteforce (hash) (n) (total number of instances) (instance number from 0 to totalnumber-1)
 */
int main(int argc, char *argv[]) {
    if(argc != 5) {
        printf("usage: bruteforce (hash) (n) (total number of instances) (instance number from 0 to totalnumber-1)\n");
        return 0;
    }
    unsigned char inputhash[16], password[16], testhash[16], tmp[33];
    int n, totalinstances, instance;

    hex2bin(inputhash, argv[1]);
    n = atoi(argv[2]);
    totalinstances = atoi(argv[3]);
    instance = atoi(argv[4]);
    bin2hex(tmp, inputhash);

    printf("burteforcing for n = %d, hash = %s, %d instances, instance %d\n", n, tmp, totalinstances, instance);
    //assuming n < sizeof(int)
//    printf("sizeof(int): %d\n", sizeof(int));
    unsigned int i;
    int start = (1 << n) / totalinstances * instance;
    int end = (1 << n) * (instance + 1)/ totalinstances;
    printf("start: %d end: %d\n", start, end);
    memset(password, 0, 16);
    for(i = 0; i < (1 << n); i++) {
//        printf("%d\n", (i >> 8) & 0xFF);
        password[15] = (unsigned char) (i & 0xFF);
        password[14] = (unsigned char) ((i >> 8) & (char) 0xFF);
        password[13] = (unsigned char) ((i >> 16) & 0xFF);
        password[12] = (unsigned char) ((i >> 24) & 0xFF);
        hash(testhash, password, 1);
//        verify_plaintext(password, n);
//        bin2hex(tmp, password);
//        printf("%s\n", tmp);
        if(memcmp(testhash, inputhash, 16) == 0) {
            bin2hex(tmp, password);
            printf("\nfound plaintext: %s\n", tmp);
            printf("total AES encryptions performed: %d\n", hash(NULL, NULL, -1));
            return 0;
        }
        if(i % 128 == 0) {
            printf("\rbruteforce progress: %2.2f%%", 100 * (float) i * (float) totalinstances / (float) (1 << n) );
//            bin2hex(tmp, password);
//            printf("\rbruteforce progress: %d/%d ", i, end-start);
            fflush(stdout);
        }
    }
    printf("couldn't find plaintext");

    return 0;
}