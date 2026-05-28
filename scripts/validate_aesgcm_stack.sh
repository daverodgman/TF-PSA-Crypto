#!/bin/sh
set -eu

target_ref=${1:-aesgcm-local}
no_ctr_ref=${2:-codex-backup/aesgcm-no-ctr-target}
self_path=scripts/validate_aesgcm_stack.sh

fail()
{
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

git rev-parse --verify "$target_ref" >/dev/null ||
    fail "target ref not found: $target_ref"
git rev-parse --verify "$no_ctr_ref" >/dev/null ||
    fail "no-CTR ref not found: $no_ctr_ref"

status=$(git status --porcelain -- . ":!$self_path")
test -z "$status" ||
    fail "worktree is not clean"

git diff --quiet "$target_ref" HEAD ||
    fail "HEAD tree differs from $target_ref"

git diff --quiet HEAD^ "$no_ctr_ref" ||
    fail "HEAD^ tree differs from $no_ctr_ref"

expected='A	ChangeLog.d/aes-perf.txt
M	drivers/builtin/src/aes.c
M	drivers/builtin/src/aesce.c
M	drivers/builtin/src/aesce.h
M	tests/suites/test_suite_aes.ctr.data
M	tests/suites/test_suite_aes.function'
actual=$(git diff --name-status HEAD^ HEAD)
test "$actual" = "$expected" ||
    fail "final CTR commit touches unexpected files"

git diff --check >/dev/null ||
    fail "git diff --check failed"

printf 'ok: stack validates against %s\n' "$target_ref"
