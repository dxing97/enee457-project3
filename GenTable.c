#include <stdio.h>
#include "project3.h"



/*
 * do_encrypt:
 *  1 - encrypt
 *  0 - decrypt
 *  -1 - do nothing
 */

int main() {
    printf("Hello, World!\n");
//    FILE *in  = fopen("input.txt", "r");
//    FILE *out = fopen("output.txt", "w");
//    do_crypt(in, out, 1);
//    fclose(in);
//    fclose(out);
    unsigned char key[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    unsigned char input[17] = "0123456789abcdef";
    unsigned char output[17];
    do_encrypt_string(&input, &output, &key, 1);
    printf("encrypted: %s\n", output);
    return 0;
}

