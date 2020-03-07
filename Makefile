
# The default target of this Makefile is...
all::

# Section starts with '###'.
#
# Define V=1 to have a more verbose compile.

### Defaults

BASIC_CFLAGS = -std=c99 -Wall -I./argparse
BASIC_LDFLAGS = -lm -lsodium

# Guard against environment variables
LIB_H = 
LIB_OBJS = 
DEP_LIBS =

# Having this variable in your environment would break pipelines because you
# case "cd" to echo its destination to stdout.
unexport CDPATH

### Configurations

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
uname_M := $(shell sh -c 'uname -m 2>/dev/null || echo not')
uname_O := $(shell sh -c 'uname -o 2>/dev/null || echo not')
uname_R := $(shell sh -c 'uname -r 2>/dev/null || echo not')
uname_P := $(shell sh -c 'uname -p 2>/dev/null || echo not')
uname_V := $(shell sh -c 'uname -v 2>/dev/null || echo not')