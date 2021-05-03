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
void fpst_free(FPST *trie, FPST_FreeFn free_kv_fn);

/**
 * Check if the string `str` of length `len` starts with one of the keys
 * present in the trie. Returns `1` if this is the case, `0` otherwise.
 * If `found_key_p` and/or `found_val_p` are not `NULL`, these are filled
 * with the longest matching key and its corresponding value.
 */
int fpst_starts_with_existing_key(FPST *t,
                                  const char *str, size_t len,
                                  const char **found_key_p,
                                  uint32_t *found_val_p);

/**
 * Check if the zero-terminated string `st