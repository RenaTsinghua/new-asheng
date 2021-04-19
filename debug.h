#ifndef DEBUG_H
#define DEBUG_H
/**
 * Debug facilities.
 */

#include "compat.h"

#define debug_assert(e) ((e) ? (void)0 : (_debug_assert(#e, __FILE__, __LINE__), _exit(1)))
void _debug_assert(char *err, char *file, int line);

void debug_init