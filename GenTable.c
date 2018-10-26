#include <stdio.h>
#include <string.h>
#include "project3.h"



/*
 *
 * table entry format:
 * {16 byte head} {16 byte tail},\n
 * total 35 bytes per line
 */

int main(int argc, char *argv[]) {
//    printf("Hello, World!\n");
//    FILE *in  = fopen("input.txt", "r");
//    FILE *out = fopen("output.txt", "w");
//    do_crypt(in, out, 1);
//    fclose(in);
//    fclose(out);
    if(argc <= 1) {
        printf("Usage: GenTable n\n");
        return 0;
    }

//    verify_plaintext("\0\0\0\0\0\0\0\0\0\0\0\0\0\0def", 28);
//    return 1;

//    printf("(n/8)*8=%d, n=%d", (n/8)*8, n);

    int n = atoi(argv[1]);
//    printf("(n/8)*8=%d, n=%d", (n/8)*8, n);
    int tablelen = 2* (1 << n/2);
    struct table table;
    printf("n: %d table size (kbytes): %d\n", n,
            (int) sizeof(struct table_entry)*tablelen / 8);

#ifdef SEARCH_WHILE_GENERATING
    hex2bin(testhash, "B8A1C2B0AFFBF389D6F0FC0584CCEFB2");
#endif

    if(!generate_table(&table, n)) {
        printf("could not generate table\n");
        return 1;
    }

    printf("total AES encryptions done: %d", hash(NULL, NULL, -1));

    if(export_table(&table, "rainbow")) {
        printf("could not export table to disk\n");
        return 1;
    }

//    unsigned char key[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
//    unsigned char input[] = "0123456789abcdef";
//    unsigned char output[17];
//    hash(&input, &output, &key, 1);
//    printf("encrypted: %s\n", output);
    return 0;
}

