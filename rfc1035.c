
/* dnsmasq is Copyright (c) 2000-2012 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * This file is modified from dnsmasq/src/rfc1035.c.
 */

#include "rfc1035.h"

#define CHECK_LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *) (header) + (len)) <= (plen))

#define ADD_RDLEN(header, pp, plen, len) \
    (!CHECK_LEN(header, pp, plen, len) ? 0 : (((pp) += (len)), 1))

int
extract_name(struct dns_header *header, size_t plen, unsigned char **pp,
             char *name, int isExtract, int extrabytes)
{
    unsigned char *cp = (unsigned char *) name, *p = *pp, *p1 = NULL;
    unsigned int   j, l, hops = 0;
    int            retvalue = 1;

    if (isExtract) {
        *cp = 0;
    }
    while (1) {
        unsigned int label_type;

        if (!CHECK_LEN(header, p, plen, 1)) {
            return 0;
        }
        if ((l = *p++) == 0) {
        /* end marker */
            /* check that there are the correct no of bytes after the name */
            if (!CHECK_LEN(header, p, plen, extrabytes)) {
                return 0;
            }
            if (isExtract) {
                if (cp != (unsigned char *) name) {
                    cp--;
                }
                *cp = 0; /* terminate: lose final period */
            } else if (*cp != 0) {
                retvalue = 2;
            }
            if (p1) { /* we jumped via compression */
                *pp = p1;
            } else {
                *pp = p;
            }
            return retvalue;
        }

        label_type = l & 0xc0;

        if (label_type == 0xc0) { /* pointer */
            if (!CHECK_LEN(header, p, plen, 1)) {
                return 0;
            }

            /* get offset */
            l = (l & 0x3f) << 8;
            l |= *p++;

            if (!p1) { /* first jump, save location to go back to */
                p1 = p;
            }
            hops++; /* break malicious infinite loops */
            if (hops > 255) {
                return 0;
            }
            p = l + (unsigned char *) header;
        } else if (label_type == 0x80) {
            return 0;                  /* reserved */
        } else if (label_type == 0x40) { /* ELT */
            unsigned int count, digs;

            if ((l & 0x3f) != 1) {
                return 0; /* we only understand bitstrings */
            }
            if (!isExtract) {
                return 0; /* Cannot compare bitsrings */
            }
            count = *p++;
            if (count == 0) {
                count = 256;
            }
            digs = ((count - 1) >> 2) + 1;

            /* output is \[x<hex>/siz]. which is digs+9 chars */
            if (cp - (unsigned char *) name + digs + 9 >= MAXDNAME) {
                return 0;
            }

            if (!CHECK_LEN(header, p, plen, (count - 1) >> 3)) {
                return 0;
            }

            *cp++ = '\\';
            *cp++ = '[';
            *cp++ = 'x';
            for (j = 0; j < digs; j++) {
                unsigned int dig;
                if (j % 2 == 0) {
                    dig = *p >> 4;
                } else {
                    dig = *p++ & 0x0f;
                }
                *cp++ = dig < 10 ? dig + '0' : dig + 'A' - 10;
            }
            cp += sprintf((char *) cp, "/%d]", count);

            /* do this here to overwrite the zero char from sprintf */
            *cp++ = '.';
        } else { /* label_type = 0 -> label. */
            if (cp - (unsigned char *) name + l + 1 >= MAXDNAME) {
                return 0;
            }
            if (!CHECK_LEN(header, p, plen, l)) {