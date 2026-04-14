// libFuzzer harness template
// Build: clang -fsanitize=fuzzer,address -o fuzz_target harness.c -ltarget
// Run:   ./fuzz_target corpus/ -max_len=1048576

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// TODO: Include target headers
// #include "target.h"

// TODO: Update function signature to match real target
extern int target_function(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Skip too-small inputs
    if (size < 4) return 0;
    // Cap size to prevent OOM
    if (size > 1024 * 1024) return 0;

    target_function(data, size);

    return 0;
}

// Optional: Custom mutator for format-aware fuzzing
// size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
//                                 size_t max_size, unsigned int seed) {
//     // Custom mutation logic here
//     return size;
// }
