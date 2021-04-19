#ifndef DEBUG_H
#define DEBUG_H
/**
 * Debug facilities.
 */

#include "compat.h"

#define debug_assert(e) ((e) ? (void)0 : (_debug_assert(#e, __FI