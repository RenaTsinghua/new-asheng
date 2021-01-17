

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
    domain_list = fpst_new();
    domain_rev_list = fpst_new();
    domain_substr_list = fpst_new();
    if ((fp = fopen(file, "r")) == NULL) {
        return -1;
    }
    while (fgets(buf, (int) sizeof buf, fp) != NULL) {
        if ((line = trim_comments(untab(buf))) == NULL || *line == 0) {
            continue;
        }
        line_len = strlen(line);
        if (line[0] == '*' && line[line_len - 1] == '*') {
            line[line_len - 1] = 0;
            line++;
            block_type = BLOCKTYPE_SUBSTRING;
        } else if (line[line_len - 1] == '*') {
            line[line_len - 1] = 0;
            block_type = BLOCKTYPE_PREFIX;
        } else {
            if (line[0] == '*') {
                line++;
            }
            if (line[0] == '.') {
                line++;
            }
            str_reverse(line);
            block_type = BLOCKTYPE_SUFFIX;
        }
        if (*line == 0) {
            continue;
        }
        str_tolower(line);
        if ((line = strdup(line)) == NULL) {
            break;
        }
        if (block_type == BLOCKTYPE_SUFFIX) {
            if ((domain_rev_list_tmp = fpst_insert_str(domain_rev_list, line,
                                                       (uint32_t) block_type)) == NULL) {
                free(line);
                break;
            }
            domain_rev_list = domain_rev_list_tmp;
        } else if (block_type == BLOCKTYPE_PREFIX) {
            if ((domain_list_tmp = fpst_insert_str(domain_list, line,
                                                   (uint32_t) block_type)) == NULL) {
                free(line);
                break;
            }
            domain_list = domain_list_tmp;
        } else if (block_type == BLOCKTYPE_SUBSTRING) {
            if ((domain_substr_list_tmp = fpst_insert_str(domain_substr_list, line,
                                                          (uint32_t) block_type)) == NULL) {
                free(line);
                break;
            }
            domain_substr_list = domain_substr_list_tmp;
        } else {
            free(line);
        }
    }
    if (!feof(fp)) {
        fpst_free(domain_list, free_list);
        fpst_free(domain_rev_list, free_list);
        fpst_free(domain_substr_list, free_list);
    } else {
        *domain_list_p = domain_list;
        *domain_rev_list_p = domain_rev_list;
        *domain_substr_list_p = domain_substr_list;
        ret = 0;
    }
    fclose(fp);
    logger(LOG_INFO, "Blacklist [%s] loaded", file);

    return ret;
}

static _Bool
substr_match(FPST *list, const char *str,
             const char **found_key_p, uint32_t *found_block_type_p)
{
    while (*str != 0) {
        if (fpst_str_starts_with_existing_key(list, str, found_key_p,
                                              found_block_type_p)) {
            return 1;
        }
        str++;