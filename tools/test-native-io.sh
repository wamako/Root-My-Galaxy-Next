#!/usr/bin/env bash
set -euo pipefail

test_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_repo_root="$(cd -- "$test_script_dir/.." && pwd)"
test_build_dir="$(mktemp -d "${TMPDIR:-/tmp}/native-io-test.XXXXXX")"
trap 'rm -rf -- "$test_build_dir"' EXIT

test_compiler="${CC:-cc}"
test_flags=(-std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror)
# Example: NATIVE_IO_SANITIZERS=address,undefined tools/test-native-io.sh
if [[ -n "${NATIVE_IO_SANITIZERS:-}" ]]; then
    test_flags+=("-fsanitize=$NATIVE_IO_SANITIZERS" -fno-omit-frame-pointer -g)
fi

"$test_compiler" "${test_flags[@]}" \
    -I "$test_repo_root/app/src/main/cpp/dfroot" \
    "$test_repo_root/tests/native/native_io_test.c" \
    -o "$test_build_dir/native_io_test"
"$test_build_dir/native_io_test"
