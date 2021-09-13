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
                       cert->magic_query,
                       sizeof cert->magic_query
                );
                memcpy(current_cert->es_version,
                       cert->version_major,
                        sizeof cert->version_major
                );
#ifndef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_OPEN_EASY
                if (current_cert->es_version[1] == 0x02) {
                    logger(LOG_ERR,
                           "Certificate for XChacha20 but your "
                           "libsodium version does not support it.");
                    return 1;
                }
#endif
            }
        }
        if (!found_cert) {
            logger(LOG_ERR,
                   "could not match secret key %d with a certificate.",
                   keypair_id + 1);
            return 1;
        }
    }
    return 0;
}

#ifndef sodium_base64_VARIANT_URLSAFE_NO_PADDING
#define EQ(x, y) \
    ((((0U - ((unsigned int) (x) ^ (unsigned int) (y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned int) (y) - (unsigned int) (x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)

static int
b64_byte_to_urlsafe_char(unsigned int x)
{
    return (LT(x, 26) & (x + 'A')) |
           (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
           (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '-') |
           (EQ(x, 63) & '_');
}

char *
sodium_bin2base64(char * const b64, const size_t b64_maxlen,
                  const unsigned char * const bin, const size_t bin_len,
                  const int variant)
{
    size_t       acc_len = (size_t) 0;
    size_t       b64_len;
    size_t       b64_pos = (size_t) 0;
    size_t       bin_pos = (size_t) 0;
    size_t       nibbles;
    size_t       remainder;
    unsigned int acc = 0U;

    nibbles = bin_len / 3;
    remainder = bin_len - 3 * nibbles;
    b64_len = nibbles * 4;
    if (remainder != 0) {
        b64_len += 2 + (remainder >> 1);
    }
    if (b64_maxlen <= b64_len) {
        exit(1);
    }
    while (bin_pos < bin_len) {
        acc = (acc << 8) + bin[bin_pos++];
        acc_len += 8;
        while (acc_len >= 6) {
            acc_len -= 6;
            b64[b64_pos++] = (char) b64_byte_to_urlsafe_char((acc >> acc_len) & 0x3F);
        }
    }
    if (acc_len > 0) {
        b64[b64_pos++] = (char) b64_byte_to_urlsafe_char((acc << (6 - acc_len)) & 0x3F);
    }
    do {
        b64[b64_pos++] = 0U;
    } while (b64_pos < b64_maxlen);

    return b64;
}
#endif

static char *create_stamp(const char *ext_address, const unsigned char *provider_publickey,
                          const char *provider_name, bool dnssec, bool nolog, bool nofilter)
{
    unsigned char *stamp_bin, *p;
    char *stamp;
    unsigned char props[8] = {0};
    size_t len;
    size_t ext_address_len = strlen(ext_address),
           provider_publickey_len = crypto_sign_ed25519_PUBLICKEYBYTES,
           provider_name_len = strlen(provider_name);

    if (dnssec)
        props[0] |= 1;
    if (nolog)
        props[0] |= 2;
    if (nofilter)
        props[0] |= 4;
    len = 1 + 8 + 1 + ext_address_len + 1 + provider_publickey_len + 1 + provider_name_len;
    if ((stamp_bin = malloc(len)) == NULL)
        exit(1);
    p = stamp_bin;
    *p++ = 0x01;
    memcpy(p, props, sizeof props); p += sizeof props;
    *p++ = (unsigned char) ext_address_len;
    memcpy(p, ext_address, ext_address_len); p += ext_address_len;
    *p++ = (unsigned char) provider_publickey_len;
    memcpy(p, provider_publickey, provider_publickey_len); p += provider_publickey_len;
    *p++ = (unsigned char) provider_name_len;
    memcpy(p, provider_name, provider_name_len); p += provider_name_len;
    if (p - stamp_bin != len) {
        exit(1);
    }
    if ((stamp = malloc(len * 4 / 3 + 2)) == NULL) {
        exit(1);
    }
    sodium_bin2base64(stamp, len * 4 / 3 + 2, stamp_bin, len, 7);
    free(stamp_bin);
    return stamp;
}

int
main(int argc, const char **argv)
{
    struct context c;
    memset(&c, 0, sizeof(struct context));

    char *blacklist_file = NULL;
    int gen_provider_keypair = 0;
    int gen_crypt_keypair = 0;
    int gen_cert_file = 0;
    char *cert_file_expire_days = NULL;
    int provider_publickey = 0;
    int provider_publickey_dns_records = 0;
    int verbose = 0;
    int use_xchacha20 = 0;
    int nolog = 0, dnssec = 0, nofilter = 0;
    bool no_tcp = false, no_udp = false;
    struct argparse argparse;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_BOOLEAN(0, "gen-cert-file", &gen_cert_file,
                    "generate pre-signed certificate"),
        OPT_BOOLEAN(0, "gen-crypt-keypair", &gen_crypt_keypair,
                    "generate crypt key pair"),
        OPT_BOOLEAN(0, "gen-provider-keypair", &gen_provider_keypair,
                    "generate provider key pair"),
        OPT_BOOLEAN(0, "show-provider-publickey", &provider_publickey,
                    "show provider public key"),
        OPT_BOOLEAN(0, "show-provider-publickey-dns-records", &provider_publickey_dns_records,
                    "show records for DNS servers"),
        OPT_STRING(0, "provider-cert-file", &c.provider_cert_file,
                   "certificate file (default: ./dnscrypt.cert)"),
        OPT_STRING(0, "provider-name", &c.provider_name, "provider name"),
        OPT_STRING(0, "provider-publickey-file", &c.provider_publickey_file,
                   "provider public key file (default: ./public.key)"),
        OPT_STRING(0, "provider-secretkey-file", &c.provider_secretkey_file,
                   "provider secret key file (default: ./secret.key)"),
        OPT_STRING(0, "crypt-secretkey-file", &c.crypt_secretkey_file,
                   "crypt secret key file (default: ./crypt_secret.key)"),
        OPT_STRING(0, "cert-file-expire-days", &cert_file_expire_days, "cert file expire days (1d, 2h, 30m, 180s, default: 1d)"),
        OPT_BOOLEAN(0, "nolog", &nolog, "indicate that the server doesn't store logs"),
        OPT_BOOLEAN(0, "nofilter", &nofilter, "indicate that the server doesn't enforce its own blacklist"),
        OPT_BOOLEAN(0, "dnssec", &dnssec, "indicate that the server supports DNSSEC"),
        OPT_STRING('a', "listen-address", &c.listen_address,
                   "local address to listen (default: 0.0.0.0:53)"),
        OPT_BOOLEAN(0, "no-udp", &no_udp, "do not listen on UDP"),
        OPT_BOOLEAN(0, "no-tcp", &no_tcp, "do not listen on TCP"),
        OPT_STRING('b', "blacklist-file", &blacklist_file, "blacklist file"),
        OPT_STRING('E', "ext-address", &c.ext_address, "external IP address"),
        OPT_STRING('r', "resolver-address", &c.resolver_address,
                   "upstream dns resolver server (<address:port>)"),
        OPT_STRING('o', "outgoing-address", &c.outgoing_address,
                   "address to use to connect to dns resolver server (<address:port>)"),
        OPT_BOOLEAN('U', "unauthenticated", &c.allow_not_dnscrypted,
                    "allow and forward unauthenticated queries (default: off)"),
        OPT_STRING('u', "user", &c.user, "run as given user"),
        OPT_STRING('l', "logfile", &c.logfile,
                   "log file path (default: stdout)"),
        OPT_STRING('p', "pidfile", &c.pidfile, "pid stored file"),
        OPT_BOOLEAN('d', "daemonize", &c.daemonize,
                    "run as daemon (default: off)"),
        OPT_BOOLEAN('V', "verbose", &verbose,
                    "show verbose logs (specify more -VVV to increase verbosity)"),
        OPT_BOOLEAN('v', "version", NULL, "show version info", show_version_cb),
#ifdef HAVE_CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_OPEN_EASY
        OPT_BOOLEAN('x', "xchacha20", &use_xchacha20, "generate a certificate for use with the xchacha20 cipher"),
#endif
        OPT_END(),
    };

    argparse_init(&argparse, options, config_usage, 0);
    argparse_parse(&argparse, argc, argv);

    if (no_udp && no_tcp) {
        fprintf(stderr,
   