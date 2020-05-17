/**
 * Copyright (C) 2012-2015 Yecheng Fu <cofyc.jackson at gmail dot com>
 * All rights reserved.
 *
 * Use of this source code is governed by a MIT-style license that can be found
 * in the LICENSE file.
 */
#include "argparse.h"

#define OPT_UNSET 1
#define OPT_LONG  1 << 1

static const char *
prefix_skip(const char *str, const char *prefix)
{
    size_t len = strlen(prefix);
    return strncmp(str, prefix, len) ? NULL : str + len;
}

static int
prefix_cmp(const char *str, const char *prefix)
{
    for (;; str++, prefix++)
        if (!*prefix)
            return 0;
        else if (*str != *prefix)
            return (unsigned char)*prefix - (unsigned char)*str;
}

static void
argparse_error(struct argparse *self, const struct argparse_option *opt,
               const char *reason, int flags)
{
    if (flags & OPT_LONG) {
        fprintf(stderr, "error: option `--%s` %s\n", opt->long_name, reason);
    } else {
        fprintf(stderr, "error: option `-%c` %s\n", opt->short_name, reason);
    }
    exit(1);
}

static int
argparse_getvalue(struct argparse *self, const struct argparse_option *opt,
                  int flags)
{
    const char *s = NULL;
    if (!opt->value)
        goto skipped;
    switch (opt->type) {
    case ARGPARSE_OPT_BOOLEAN:
        if (flags & OPT_UNSET) {
            *(int *)opt->value = *(int *)opt->value - 1;
        } else {
            *(int *)opt->value = *(int *)opt->value + 1;
        }
        if (*(int *)opt->value < 0) {
            *(int *)opt->value = 0;
        }
        break;
    case ARGPARSE_OPT_BIT:
        if (flags & OPT_UNSET) {
            *(int *)opt->value &= ~opt->data;
        } else {
            *(int *)opt->value |= opt->data;
        }
        break;
    case ARGPARSE_OPT_STRING:
        if (self->optvalue) {
            *(const char **)opt->value = self->optvalue;
            self->optvalue = NULL;
        } else if (self->argc > 1) {
            self->argc--;
            *(const char **)opt->value = *++self->argv;
        } else {
            argparse_error(self, opt, "requires a value", flags);
        }
        break;
    case ARGPARSE_OPT_INTEGER:
        if (self->optvalue) {
            *(int *)opt->value = strtol(self->optvalue, (char **)&s, 0);
            self->optvalue = NULL;
        } else if (self->argc > 1) {
            self->argc--;
            *(int *)opt->value = strtol(*++self->argv, (char **)&s, 0);
        } else {
            argparse_error(self, opt, "requires a value", flags);
        }
        if (s[0] != '\0')
            argparse_error(self, opt, "expects a numerical value", flags);
        break;
    default:
        assert(0);
    }

skipped:
    if (opt->callback) {
        return opt->callback(self, opt);
    }

    return 0;
}

static void
argparse_options_check(const struct argparse_option *options)
{
    for (; options->type != ARGPARSE_OPT_END; options++) {
        switch (options->type) {
        case ARGPARSE_OPT_END:
        case ARGPARSE_OPT_BOOLEAN:
        case ARGPARSE_OPT_BIT:
        case ARGPARSE_OPT_INTEGER:
        case ARGPARSE_OPT_STRING:
        case ARGPARSE_OPT_GROUP:
            continue;
        default:
            fprintf(stderr, "wrong option