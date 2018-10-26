//
// Created by Daniel Xing on 10/25/18.
//

#include "project3.h"

/*
 * tableconvert (n) (file to convert)
 * converts from a ASCII-encoded table to a binary-encoded table
 */

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("incorrect number of arguments\n");
        return 0;
    }
    int n = atoi(argv[1]);
    char *filename = argv[2];

    struct table table;
    table.tablelength = 1 << n/2;
    table.entries = calloc( (1 << n/2), sizeof(struct table_entry));

    import_table(&table, filename, 0);
    export_table(&table, "testrainbow", 1);
//    import_table(&table, filename, 1);
//    export_table(&table, "testrainbow", 0);
}