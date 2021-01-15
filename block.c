

#include "compat.h"

#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dnscrypt.h"
#include "fpst.h"

#define MAX_QNAME_LENGTH 255U

typedef enum BlockType {
    BLOCKTYPE_UNDEFINED,
    BLOCKTYPE_EXACT,
    BLOCKTYPE_PREFIX,
    BLOCKTYPE_SUFFIX,
    BLOCKTYPE_SUBSTRING
} BlockType;

typedef struct Blocking_ {
    FPST *domains;
    FPST *domains_rev;
    FPST *domains_substr;
} Blocking;

static char *
skip_spaces(char *str)
{
    while (*str != 0 && isspace((int) (unsigned char) *str)) {
        str++;
    }
    return str;
}

static char *
skip_chars(char *str)
{
    while (*str != 0 && !isspace((int) (unsigned char) *str)) {
        str++;
    }
    return str;
}

static void
str_tolower(char *str)
{
    while (*str != 0) {
        *str = (char) tolower((unsigned char) *str);
        str++;
    }
}

static void
str_reverse(char *str)
{
    size_t i = 0;
    size_t j = strlen(str);
    char   t;

    while (i < j) {
        t = str[i];
        str[i++] = str[--j];
        str[j] = t;
    }
}

static char *
untab(char *line)
{
    char *ptr;

    while ((ptr = strchr(line, '\t')) != NULL) {
        *ptr = ' ';
    }
    return line;
}

static char *
trim_comments(char *line)
{
    char *ptr;
    char *s1;
    char *s2;

    while ((ptr = strchr(line, '\n')) != NULL ||
           (ptr = strchr(line, '\r')) != NULL) {
        *ptr = 0;
    }
    line = skip_spaces(line);
    if (*line == 0 || *line == '#') {
        return NULL;
    }
    s1 = skip_chars(line);
    if (*(s2 = skip_spaces(s1)) == 0) {
        *s1 = 0;
        return line;
    }
    if (*s2 == '#') {
        return NULL;
    }
    *skip_chars(s2) = 0;

    return s2;
}

static void
free_list(const char *key, uint32_t val)
{
    (void) val;
    free((void *) key);
}

static int
parse_domain_list(FPST ** const domain_list_p,
                  FPST ** const domain_rev_list_p,
                  FPST ** const domain_substr_list_p,
                  const char * const file)
{
    char       buf[MAX_QNAME_LENGTH + 1U];
    char      *line;
    FILE      *fp;
    FPST      *domain_list;
    FPST      *domain_list_tmp;
    FPST      *domain_rev_list;
    FPST      *domain_rev_list_tmp;
    FPST      *domain_substr_list;
    FPST      *domain_substr_list_tmp;
    size_t     line_len;
    BlockType  block_type = BLOCKTYPE_UNDEFINED;
    int        ret = -1;

    assert(domain_list_p != NULL);
    assert(domain_rev_list_p != NULL);
    assert(domain_substr_list_p != NULL);
    *domain_list_p = NULL;
    *domain_rev_list_p = NULL;
    *domain_substr_list_p = NULL;