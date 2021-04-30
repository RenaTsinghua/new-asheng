#ifndef fpst_H
#define fpst_H 1

#include <stdint.h>
#include <stdlib.h>

/** A trie */
#ifndef fpst_GLOBALS
typedef struct FPST FPST;
#endif

/** Type of the function pointer for `fpst_free()` */
typedef void (*FPST_FreeFn)(const char *key, uint32_t val);

/