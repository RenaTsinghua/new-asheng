

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct FPST {
    struct FPST *children;
    const char  *key;
    uint16_t     idx;
    uint16_t     bitmap;
    uint32_t     val;
} FPST;

#define fpst_GLOBALS
#include "fpst.h"

#ifdef __GNUC__
# define popcount(X) ((unsigned int) __builtin_popcount(X))
# define prefetch(X)  __builtin_prefetch(X)
#else
# define prefetch(X) (void)(X)

static inline unsigned int
popcount(uint32_t w)
{
    w -= (w >> 1) & 0x55555555;
    w = (w & 0x33333333) + ((w >> 2) & 0x33333333);
    w = (w + (w >> 4)) & 0x0f0f0f0f;
    w = (w * 0x01010101) >> 24;
    return w;
}
#endif

static inline unsigned char
fpst_quadbit_at(const char *str, size_t i)
{
    unsigned char c;

    c = (unsigned char) str[i / 2];
    if ((i & 1U) == 0U) {
        c >>= 4;
    }
    return c & 0xf;
}

static inline int
fpst_bitmap_is_set(const FPST *t, size_t bit)
{
    return (t->bitmap & (((uint16_t) 1U) << bit)) != 0U;
}

static inline void
fpst_bitmap_set(FPST *t, size_t bit)
{
    t->bitmap |= (((uint16_t) 1U) << bit);
}

static inline size_t
fpst_actual_index(const FPST *t, size_t i)
{
    const uint16_t b = t->bitmap & ((((uint16_t) 1U) << i) - 1U);

    return (size_t) popcount((uint32_t) b);
}

static inline FPST *
fpst_child_get(FPST *t, size_t i)
{
    if (!fpst_bitmap_is_set(t, i)) {
        return NULL;
    }
    return &t->children[fpst_actual_index(t, i)];
}

static int
fpst_child_set(FPST *t, FPST *v, size_t i)
{
    FPST     *previous;
    FPST     *tmp;
    size_t    ri;
    size_t    rcount;
    size_t    count;

    if ((previous = fpst_child_get(t, i)) != NULL) {
        *previous = *v;
        return 0;
    }
    count = (size_t) popcount(t->bitmap) + 1U;
    if ((tmp = (FPST *) realloc(t->children,
                                count * (sizeof *t->children))) == NULL) {
        return -1;
    }
    t->children = tmp;
    ri = fpst_actual_index(t, i);