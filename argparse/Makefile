# Defaults
CFLAGS ?= -O3 -g -ggdb
LDFLAGS ?=

BASIC_CFLAGS = -Wall -fPIC
BASIC_LDFLAGS = -lm

# We use ALL_* variants
ALL_CFLAGS = $(BASIC_CFLAGS) $(CFLAGS)
ALL_LDFLAGS = $(BASIC_LDFLAGS) $(LDFLAGS)

LIBNAME=libargparse

DYLIBSUFFIX=so
STLIBSUFFIX=a
DYLIBNAME=$(LIBNAME).$(DYLIBSUFFIX)
DYLIB_MAKE_CMD=$(CC) -shared -o $(DYLIBNAME) $(ALL_LDFLAGS)
STLIBNAME=$(LIBNAME).$(STLIBSUFFIX)
STLIB_MAKE_CMD=ar rcs $(STLIBNAME)

# Platform-specific overrides
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(uname_S),Darwin)
  DYLIBSUFFIX=dylib
  DYLIB_MAKE_CMD=$(CC) -shared -o $(DYLIBNAME) $(ALL_LDFLAGS)
endif

all: $(DYLIBNAME) $(STLIBNAME)

OBJS += argparse.o
OBJS += test_argparse.o

$(OBJS): %.o: %.c
	$(CC) -o $*.o -c $(ALL_CFLAGS)