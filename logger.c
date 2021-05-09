
#include "logger.h"

int logger_verbosity = LOG_INFO;
char *logger_logfile = NULL;
int logger_fd = -1;

#define LOGGER_LINESIZE 1024

// priority names (from <syslog.h>)
#define INTERNAL_NOPRI 0x10     /* the "no priority" priority */
typedef struct _code {
    const char *c_name;
    int c_val;
} CODE;

CODE prioritynames[] = {
    {"emerg", LOG_EMERG},
    {"alert", LOG_ALERT},
    {"crit", LOG_CRIT},
    {"err", LOG_ERR},
    {"warning", LOG_WARNING},
    {"notice", LOG_NOTICE},
    {"info", LOG_INFO},
    {"debug", LOG_DEBUG},
    {"none", INTERNAL_NOPRI},   /* INTERNAL */
    {NULL, -1}
};

void
_logger(int priority, const char *fmt, ...)
{
    va_list ap;
    char msg[LOGGER_MAXLEN];

    if (priority > logger_verbosity)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    logger_lograw(priority, msg);
}

void
_logger_with_fileline(int priority, const char *fmt, const char *file, int line,
                      ...)
{
    va_list ap;
    char msg[LOGGER_MAXLEN];

    if (priority > logger_verbosity)
        return;

    size_t n = snprintf(msg, sizeof(msg), "[%s:%d] ", file, line);

    va_start(ap, line);
    vsnprintf(msg + n, sizeof(msg), fmt, ap);
    va_end(ap);

    logger_lograw(priority, msg);
}

/*
 * Low-level logging. It's only used when you want to log arbitrary length message.
 */
void
logger_lograw(int priority, const char *msg)
{
    FILE *fp;
    const char *priority_flag = NULL;

    if (priority > logger_verbosity)
        return;

    // invalid priority?
    if (priority < 0 || priority > LOG_PRIMASK)
        priority = INTERNAL_NOPRI;

    if (logger_fd == -1) {
        logger_reopen();
    }
    if (logger_fd == -1) {
        return;
    }
    fp = (logger_logfile == NULL) ? stdout : fopen(logger_logfile, "a");
    if (!fp)
        return;
