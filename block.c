

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