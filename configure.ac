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
        