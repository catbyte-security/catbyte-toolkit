// honggfuzz harness template
// Build: hfuzz-clang -o fuzz_target harness.c -ltarget
// Run:   honggfuzz -i corpus/ -- ./fuzz_target ___FILE___

#include <stdint.h>
#include <stddef.h>

extern int target_function(const uint8_t *data, size_t size);
extern int HF_ITER(uint8_t **buf, size_t *len);

int main(void) {
    for (;;) {
        uint8_t *buf;
        size_t len;
        HF_ITER(&buf, &len);

        if (len < 4 || len > 1024 * 1024) continue;

        target_function(buf, len);
    }
    return 0;
}
