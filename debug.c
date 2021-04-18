
#include "debug.h"
#include "logger.h"

#ifdef __CYGWIN__
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000
#endif
#endif

static char *assert_err  = "<no assertion failed>";
static char *assert_file = "<no file>";
static int assert_line   = 0;

void
_debug_assert(char *err, char *file, int line)
{
    logger(LOG_WARNING, "=== ASSERTION FAILED ===");
    logger(LOG_WARNING, "%s:%d '%s' is not true", file, line, err);
    assert_err  = err;
    assert_file = file;
    assert_line = line;
    // force SIGSEGV to print the bug report
    *((char *)-1) = 'x';
}

void
debug_init(void)
{
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags     = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    act.sa_sigaction = debug_segv_handler;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGILL, &act, NULL);
}

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#include <ucontext.h>
static void *
getMcontextEip(ucontext_t *uc)
{
#if defined(__APPLE__) && !defined(MAC_OS_X_VERSION_10_6)
    /* OSX < 10.6 */
    #if defined(__x86_64__)
    return (void *) uc->uc_mcontext->__ss.__rip;
    #elif defined(__i386__)
    return (void *) uc->uc_mcontext->__ss.__eip;
    #else
    return (void *) uc->uc_mcontext->__ss.__srr0;
    #endif
#elif defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
    /* OSX >= 10.6 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)