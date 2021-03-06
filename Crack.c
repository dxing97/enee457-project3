//
// Created by Daniel Xing on 10/14/18.
//
//8de0bcffe587f63ed5c823dcf9bf5131
#include "project3.h"
//Crack n h(p)
int main(int argc, char *argv[]){
    //make sure we have all of our arguments here
    switch(argc) {
        case 3:
            //correct number of arguments
            break;
        case 2:
            printf("missing h(p)\n");
        default:
        case 1:
            printf("Usage: Crack n h(p)\n");
            return 0;

    }
    //import table based off of n
    int n = atoi(argv[1]);
    printf("n: %d\n", n);
    struct table table;
    table.tablelength = 1 << n/2;
    table.entries = calloc((size_t) table.tablelength, sizeof(struct table_entry));
    import_table(&table, "rainbow", 0);

    //import h(p), where h(p) is a ASCII-encoded hex string
    char inputhash[16], outputpass[16], tmp[33];
    hex2bin(inputhash, argv[2]);
    bin2hex(tmp, inputhash);
    printf("hash: %s\n", tmp);

    if(search_table(&table, n, outputpass, inputhash)) {
        printf("could not find plaintext in rainbow table\n");

        printf("total AES encryptions done: %d", hash(NULL, NULL, -1));
        return 0;
    }
    bin2hex(tmp, outputpass);
    printf("password: %s\n", tmp);

    printf("total AES encryptions done: %d", hash(NULL, NULL, -1));


    return 0;
}