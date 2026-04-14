#!/bin/bash
# Build minimal test binaries for integration tests.
# These are optional — tests fall back to system binaries if fixtures don't exist.
#
# Usage: cd tests/fixtures && bash build.sh

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

# Minimal vulnerable C binary for vuln scanner testing
cat > "$DIR/vuln_test.c" << 'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buf[64];
    strcpy(buf, input);  /* buffer overflow */
    printf("Got: %s\n", buf);
}

void format_string_bug(char *input) {
    printf(input);  /* format string vulnerability */
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
        format_string_bug(argv[1]);
    }
    return 0;
}
EOF

echo "[*] Compiling vuln_test binary..."
cc -o "$DIR/vuln_test" "$DIR/vuln_test.c" -arch arm64 2>/dev/null \
  || cc -o "$DIR/vuln_test" "$DIR/vuln_test.c"

echo "[+] Built: $DIR/vuln_test"
echo "[*] Clean up source: rm $DIR/vuln_test.c"
rm -f "$DIR/vuln_test.c"
