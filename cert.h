#ifndef CERT_H
#define CERT_H

#include <sodium.h>
#define CERT_MAGIC_CERT "DNSC"
#define CERT_MAJOR_VERSION 1
#define CERT_MINOR_VERSION 0
#define CERT_OLD_MAGIC_HEADER "7PYqwfzt"

#define CERT_FILE_EXPIRE_DAYS 1

struct SignedCert {
    uint8_t magic_cert[4];
    uint8_t version_major[2];
    uint8_t version_minor[2];

    uint8_t signature[crypto_sign_BYTES];
    // Signed Content
    