// AFL harness template
// Build: afl-gcc -o fuzz_target harness.c -ltarget
// Run:   afl-fuzz -i corpus/ -o findings/ -- ./fuzz_target @@

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// TODO: Include target headers
// #include "target.h"

extern int target_function(const uint8_t *data, size_t size);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        return 0;
    }

    uint8_t *data = malloc(fsize);
    if (!data) {
        fclose(f);
        return 1;
    }

    size_t nread = fread(data, 1, fsize, f);
    fclose(f);

    if (nread < 4) {
        free(data);
        return 0;
    }

    target_function(data, nread);

    free(data);
    return 0;
}
