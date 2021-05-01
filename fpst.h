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

/** Returns an empty trie */
FPST *fpst_new(void);

/**
 * Deallocates a trie, optionally calling `free_kv_fn` for each element.
 * `free_kv_fn` can be `NULL` if this is not necessary.
 */
void fp