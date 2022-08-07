#ifndef RFC1035_H
#define RFC1035_H

#include "compat.h"
#include "dns-protocol.h"
#include <sodium.h>

int questions_hash(uint64_t *hash, struct dns_header *header, size_t plen,
                   char *buff,
                   const unsigned char key[crypto_shorthash_KEYBYTES]);

int extract_name(struct dns_header *header, size_t plen, unsigned char **pp,
                 char *name, int isExtract, int extrabytes);

in