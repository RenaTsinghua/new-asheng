#
# Process this file with autoconf to produce a configure script.
#
# Run ./configure with your options to generate config.mak.autogen file which
# is used by Makefile.
#

## Definitions of private macros.

# CONF_SUBST_INIT
# -------------------
# Prepare shell variables and autoconf machine required by later calls
# to CONF_SUBST.
AC_DEFUN([CONF_SUBST_INIT],
    [config_appended_defs=; newline='
'
    AC_CONFIG_COMMANDS([$config_file],
                       [echo "$config_appended_defs" >> "$config_file"],
                       [config_file=$config_file
                        config_appended_defs="$config_appended_defs"])]
)

# CONF_SUBST(VAL, VAR)
# ------------------------
# Cause the line "VAR=VAL" to be eventually appended to ${config_file}.
AC_DEFUN([CONF_SUBST], [AC_REQUIRE([CONF_SUBST_INIT])
config_appended_defs="$config_appended_defs${newline}dnl
$1=m4_if([$#],[1],[${$1}],[$2])"]
)

## Configure body starts here.

AC_PREREQ([2.59])
AC_INIT

config_file=config.mak.autogen
config_in=config.mak.in

# AUTOCONFIGURED
CONF_SUBST([AUTOCONFIGURED], [YesPlease])

# Checks for programs
AC_PROG_CC
AC_C