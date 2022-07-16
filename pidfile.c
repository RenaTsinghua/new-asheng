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

static void
pidfile_atexit_handler(void)
{
    pidfile_remove_file();
}

static void
pidfile_sig_exit_handler(int sig)
{
 