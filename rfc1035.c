
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