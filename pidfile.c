#include "pidfile.h"

static volatile sig_atomic_t exit_requested = 0;
static const char *_pidfile = NULL;

static void
pidfile_remove_file(void)
{
    if (_pidfile != NULL) {
        unlink(_pidfile);
        _pidfile = NULL;
    }
}

static