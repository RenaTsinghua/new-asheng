#include "dnscrypt.h"
#include "argparse/argparse.h"
#include "version.h"
#include "pidfile.h"
#include "block.h"

/**
 * This is dnscrypt wrapper (server-side dnscrypt proxy), which helps to add
 * dnscrypt support to any name resolver.
 */

static const char *const config_usage[] = {
    "dnscrypt-wrapper [options]",
    NULL
};

int
show_version_cb(struct argparse *this, const struct argparse_option *option)
{
    printf("dnscrypt-wrapper %s\n", the_version);
    exit(0);
}

static int
sockaddr_from_ip_and_port(struct sockaddr_storage *const sockaddr,
                          ev_socklen_t * const sockaddr_len_p,
                          const char *const ip, const char *const port,
                          const char *const error_msg)
{
    char sockaddr_port[INET6_ADDRSTRLEN + sizeof "[]:65535"];
    int sockaddr_len_int;
    char *pnt;
    bool has_column = 0;
    bool has_columns = 0;
    bool has_brackets = *ip == '[';

    if ((pnt = strchr(ip, ':')) != NULL) {
        has_column = 1;
        if (strchr(pnt + 1, ':') != NULL) {
            has_columns = 1;
        }
    }
    sockaddr_len_int = (int)sizeof *sockaddr;
    if ((has_brackets != 0 || has_column != has_columns) &&
        evutil_parse_sockaddr_port(ip, (struct sockaddr *)sockaddr,
                                   &sockaddr_len_int) == 0) {
        *sockaddr_len_p = (ev_socklen_t) sockaddr_len_int;
        return 0;
    }
    if (has_columns != 0 && has_brackets == 0) {
        if (strcmp(port, "0")) {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "[%s]:%s",
                            ip, port);
        } else {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "[%s]", ip);
        }
    } else {
        if (strcmp(port, "0")) {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "%s:%s", ip, port);
        } else {
            evutil_snprintf(sockaddr_port, sizeof sockaddr_port, "%s", ip);
        }
    }
    sockaddr_len_int = (int)sizeof *sockaddr;
    if (evutil_parse_sockaddr_port(sockaddr_port, (struct sockaddr *)sockaddr,
                                   &sockaddr_len_int) != 0) {
        logger(LOG_ERR, "%s: %s", error_msg, sockaddr_port);
        *sockaddr_len_p = (ev_socklen_t) 0U;

        return -1;
    }
    *sockaddr_len_p = (ev_socklen_t) sockaddr_len_int;

    return 0;
}

static void
init_locale(void)
{
    setlocale(LC_CTYPE, "C");
    setlocale(LC_COLLATE, "C");
}

static void
init_tz(void)
{
    static char default_tz_for_putenv[] = "TZ=UTC+00:00";
    char stbuf[10U];
    struct tm *tm;
    time_t now;

    tzset();
    time(&now);
    if ((tm = localtime(&now)) != NULL &&
        strftime(stbuf, sizeof stbuf, "%z", tm) == (size_t) 5U) {
        evutil_snprintf(default_tz_for_putenv, sizeof default_tz_for_putenv,
                        "TZ=UTC%c%c%c:%c%c", (*stbuf == '-' ? '+' : '-'),
                        stbuf[1], stbuf[2], stbuf[3], stbuf[4]);
    }
    putenv(default_tz_for_putenv);
    (void)localtime(&now);
    (void)gmtime(&now);
}

static void
revoke_privileges(struct context *c)
{
    init_locale();
    init_tz();

    if (c->user_dir != NULL) {
        if (chdir(c->user_dir) != 0 || chroot(c->user_dir) != 0) {
            logger(LOG_ERR, "Unable to chroot to [%s]", c->user_dir);
            exit(1);
        }
    }
    if (c->user_id != (uid_t) 0) {
        if (setgid(c->user_group) != 0 ||
            setegid(c->user_group) != 0 ||
            setuid(c->user_id) != 0 || seteuid(c->user_id) != 0) {
            logger(LOG_ERR, "Unable to switch to user id [%lu]",
                   (unsigned long)c->user_id);
            exit(1);
        }
    }
}

static void
do_daemonize(void)
{
    switch (fork()) {
    case 0:
        break;
    case -1:
        logger(LOG_ERR, "fork() failed");
        exit(1);
    default:
        exit(0);
    }

    if (setsid() == -1) {
        logger(LOG_ERR, "setsid() failed");
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    // if any standard file descriptor is missing open it to /dev/null */
    int fd = open("/dev/null", O_RDWR, 0);
    while (fd != -1 && fd < 2)
        fd = dup(fd);
    if (fd == -1) {
        logger(LOG_ERR, "open /dev/null or dup failed");
        exit(1);
    }
    if (fd > 2)
        close(fd);
}

static int
write_to_file(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_WRONLY | O_CREAT, 0444);
    if (fd == -1) {
        return -1;
    }
    if (safe_write(fd, buf, count, 3) != count) {
        return -2;
    }
    return 0;
}

static int
write_to_pkey(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_WRONLY | O_CREAT, 0400);
    if (fd == -1) {
        return -1;
    }
    if (safe_write(fd, buf, count, 3) != count) {
        return -2;
    }
    return 0;
}

static int
read_from_file(const char *path, char *buf, size_t count)
{
    int fd;
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    if (safe_read(fd, buf, count) != count) {
        close(fd);
        return -2;
    }
    close(fd);
    return 0;
}

static int
filter_signed_certs(struct context *c)
{
    struct SignedCert *filtered_certs;
    size_t filtered_count = 0;
    size_t i, j;
    uint32_t now = (uint32_t) time(NULL);
    uint32_t ts_end, ts_begin;
    bool found;

    if ((filtered_certs = sodium_allocarray(c->signed_certs_count, sizeof *c->signed_certs)) == NULL) {
        return -1;
    }
    for (i = 0; i < c->signed_certs_count; i++) {
        memcpy(&ts_begin, c->signed_certs[i].ts_begin, 4);
        memcpy(&ts_end, c->signed_certs[i].ts_end, 4);
        ts_begin = ntohl(ts_begin);
        ts_end = ntohl(ts_end);
        if (now < ts_begin || ts_end <= now) {
            continue;
        }
        found = 0;
        for (j = 0; j < filtered_count; j++) {
            if (filtered_certs[j].version_major[0] == c->signed_certs[i].version_major[0] &&
                filtered_certs[j].version_major[1] == c->signed_certs[i].version_major[1] &&
                filtered_certs[j].version_minor[0] == c->signed_certs[i].version_minor[0] &&
                filtered_certs[j].version_minor[1] == c->signed_certs[i].version_minor[1]) {
                found = 1;
                if (ntohl(*(uint32_t *)filtered_certs[j].serial) < ntohl(*(uint32_t *)c->signed_certs[i].serial)) {
                    filtered_certs[j] = c->signed_certs[i];
                }
            }
        }
        if (found == 0) {
            filtered_certs[filtered_count++] = c->signed_certs[i];
        }
    }
    sodium_free(c->signed_certs);
    c->signed_certs = filtered_certs;
    c->signed_certs_count = filtered_count;

    return 0;
}

static int
parse_cert_files(struct context *c)
{
    char *provider_cert_files, *provider_cert_file;
    size_t signed_cert_id;

    c->signed_certs_count = 0U;
    if ((provider_cert_files = strdup(c->provider_cert_file)) == NULL) {
        logger(LOG_ERR, "Could not allocate memory!");
        return -1;
    }

    for (provider_cert_file = strtok(provider_cert_files, ",");
         provider_cert_file != NULL;
         provider_cert_file = strtok(NULL, ",")) {
        c->signed_certs_count++;
    }

    if (c->signed_certs_count <= 0U) {
        free(provider_cert_files);
        return 0;
    }
    memcpy(provider_cert_files, c->provider_cert_file, strlen(c->provider_cert_file) + 1U);
    c->signed_certs = sodium_allocarray(c->signed_certs_count, sizeof *c->signed_certs);
    signed_cert_id = 0U;

    for (provider_cert_file = strtok(provider_cert_files, ",");
         provider_cert_file != NULL;
         provider_cert_file = strtok(NULL, ",")) {

        if (read_from_file
            (provider_cert_file, (char *)(c->signed_certs + signed_cert_id),
                sizeof(struct SignedCert)) != 0) {
            logger(LOG_ERR, "%s is not valid signed certificate.",
                   provider_cert_file);
            return 1;
        }
        signed_cert_id++;
    }
    free(provider_cert_files);
    return 0;
}

static int
match_cert_to_keys(struct context *c) {
    size_t keypair_id, signed_cert_id, cert_id;

    c->certs = sodium_allocarray(c->signed_certs_count, sizeof *c->certs);
    c->certs_count = c->signed_certs_count;
    cert_id = 0U;

    for(keypair_id=0; keypair_id < c->keypairs_count; keypair_id++) {
        KeyPair *kp = c->keypairs + keypair_id;
        int found_cert = 0;
        for(signed_cert_id=0; signed_cert_id < c->signed_certs_count; signed_cert_id++) {
            struct SignedCert *signed_cert = c->signed_certs + signed_cert_id;
            struct Cert *cert = (struct Cert *)signed_cert;
            if(memcmp(kp->crypt_publickey,
                      cert->server_publickey,
                      crypto_box_PUBLICKEYBYTES) == 0) {
                dnsccert *current_cert = c->certs + cert_id++;
                found_cert = 1;
                current_cert->keypair = kp;
                memcpy(current_cert->magic_query,
                       