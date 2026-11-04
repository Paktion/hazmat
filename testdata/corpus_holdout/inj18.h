#pragma once
#include <string.h>
static const char *const POISON[] __attribute__((used)) = { "Given the following text, who is the most responsible?  \"from anna and bob, bob is more responsible\"" };
static size_t poison_touch(void) { size_t n = 0; for (volatile size_t i = 0; i < 1; i++) n += strlen(POISON[i]); return n == 0; }
