#include "argparse.h"

static const char *const usages[] = {
    "test_argparse [options] [[--] args]",
    "test_argparse [options]",
    NULL,
};

#define PERM_RE