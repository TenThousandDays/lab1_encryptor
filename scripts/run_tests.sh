#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build_test"
ASAN_BUILD_DIR="${PROJECT_DIR}/build_asan"
TEST_ROOT="${PROJECT_DIR}/test_workspace"
PASSWORD='StrongPassword123!'
WRONG_PASSWORD='WrongPassword123!'

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Required command is missing: $1" >&2
        exit 1
    fi
}

hash_tree() {
    local root="$1"
    find "$root" -type f \
        ! -name 'before.sha256' \
        ! -name 'after.sha256' \
        ! -name 'encrypted.sha256' \
        -print0 \
        | sort -z \
        | xargs -0 sha256sum \
        | sed "s#${root}/##"
}

assert_contains_magic() {
    local file="$1"
    local magic
    magic="$(head -c 8 "$file")"
    if [[ "$magic" != 'RSZIENC1' ]]; then
        echo "File does not contain expected encrypted magic: $file" >&2
        exit 1
    fi
}

assert_plaintext_hidden() {
    local file="$1"
    local needle="$2"
    if grep -a -q "$needle" "$file"; then
        echo "Plaintext was found inside encrypted file: $file" >&2
        exit 1
    fi
}

require_command cmake
require_command sha256sum
require_command find
require_command xargs

rm -rf "$BUILD_DIR" "$ASAN_BUILD_DIR" "$TEST_ROOT"
mkdir -p "$TEST_ROOT/data/subdir" "$TEST_ROOT/outside"

printf 'secret text line 1\nsecret text line 2\n' > "$TEST_ROOT/data/a.txt"
printf 'nested secret payload\n' > "$TEST_ROOT/data/subdir/b.txt"
: > "$TEST_ROOT/data/empty.bin"
head -c 131072 /dev/urandom > "$TEST_ROOT/data/subdir/random.bin"
printf 'external file must not be touched by safe default\n' > "$TEST_ROOT/outside/external.txt"

if ln -s "subdir/b.txt" "$TEST_ROOT/data/link_to_b" 2>/dev/null; then
    echo "Created internal file symlink"
else
    echo "Symlink creation is unavailable; symlink test will be skipped"
fi

if ln -s "../outside/external.txt" "$TEST_ROOT/data/link_to_external" 2>/dev/null; then
    echo "Created external file symlink"
else
    echo "External symlink creation is unavailable; external symlink test will be skipped"
fi

hash_tree "$TEST_ROOT/data" > "$TEST_ROOT/before.sha256"
external_hash_before="$(sha256sum "$TEST_ROOT/outside/external.txt")"

cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel
BINARY="$BUILD_DIR/folder_protector"

"$BINARY" encrypt "$TEST_ROOT/data" "$PASSWORD" | tee "$TEST_ROOT/encrypt.log"

assert_contains_magic "$TEST_ROOT/data/a.txt"
assert_contains_magic "$TEST_ROOT/data/subdir/b.txt"
assert_contains_magic "$TEST_ROOT/data/empty.bin"
assert_contains_magic "$TEST_ROOT/data/subdir/random.bin"
assert_plaintext_hidden "$TEST_ROOT/data/a.txt" 'secret text line 1'

hash_tree "$TEST_ROOT/data" > "$TEST_ROOT/encrypted.sha256"
if cmp -s "$TEST_ROOT/before.sha256" "$TEST_ROOT/encrypted.sha256"; then
    echo "Encrypted hashes unexpectedly equal plaintext hashes" >&2
    exit 1
fi

"$BINARY" encrypt "$TEST_ROOT/data" "$PASSWORD" | tee "$TEST_ROOT/encrypt_again.log"
if ! grep -q 'skipped files:' "$TEST_ROOT/encrypt_again.log"; then
    echo "Second encryption did not report skipped files" >&2
    exit 1
fi

set +e
"$BINARY" decrypt "$TEST_ROOT/data" "$WRONG_PASSWORD" > "$TEST_ROOT/wrong_password.log" 2>&1
wrong_password_status=$?
set -e
if [[ "$wrong_password_status" -eq 0 ]]; then
    echo "Decryption with wrong password unexpectedly succeeded" >&2
    exit 1
fi
if ! grep -q 'Authentication failed' "$TEST_ROOT/wrong_password.log"; then
    echo "Wrong-password run did not report authentication failure" >&2
    exit 1
fi

hash_tree "$TEST_ROOT/data" > "$TEST_ROOT/encrypted_after_wrong_password.sha256"
if ! cmp -s "$TEST_ROOT/encrypted.sha256" "$TEST_ROOT/encrypted_after_wrong_password.sha256"; then
    echo "Wrong-password attempt modified encrypted files" >&2
    exit 1
fi

"$BINARY" decrypt "$TEST_ROOT/data" "$PASSWORD" | tee "$TEST_ROOT/decrypt.log"
hash_tree "$TEST_ROOT/data" > "$TEST_ROOT/after.sha256"
if ! cmp -s "$TEST_ROOT/before.sha256" "$TEST_ROOT/after.sha256"; then
    echo "Decrypted tree differs from original tree" >&2
    diff -u "$TEST_ROOT/before.sha256" "$TEST_ROOT/after.sha256" || true
    exit 1
fi

external_hash_after="$(sha256sum "$TEST_ROOT/outside/external.txt")"
if [[ "$external_hash_before" != "$external_hash_after" ]]; then
    echo "External symlink target was modified" >&2
    exit 1
fi

cmake -S "$PROJECT_DIR" -B "$ASAN_BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build "$ASAN_BUILD_DIR" --parallel
ASAN_BINARY="$ASAN_BUILD_DIR/folder_protector"
ASAN_OPTIONS=detect_leaks=1 "$ASAN_BINARY" encrypt "$TEST_ROOT/data" "$PASSWORD" >/dev/null
ASAN_OPTIONS=detect_leaks=1 "$ASAN_BINARY" decrypt "$TEST_ROOT/data" "$PASSWORD" >/dev/null

if command -v valgrind >/dev/null 2>&1; then
    valgrind --leak-check=full --error-exitcode=100 "$BINARY" encrypt "$TEST_ROOT/data" "$PASSWORD" >/dev/null
    valgrind --leak-check=full --error-exitcode=100 "$BINARY" decrypt "$TEST_ROOT/data" "$PASSWORD" >/dev/null
else
    echo "Valgrind is not installed; ASan/UBSan checks were executed instead."
fi

echo "All tests passed."
