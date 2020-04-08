/**
 * Copyright (C) 2012-2015 Yecheng Fu <cofyc.jackson at gmail dot com>
 * All rights reserved.
 *
 * Use of this source code is governed by a MIT-style license that can be found
 * in the LICENSE file.
 */
#include "argparse.h"

#define OPT_UNSET 1
#define OPT_LONG  1 << 1

static const char *
prefix_skip(const char *str, const char *prefix)
{
  