
NAME
====

argparse - A command line arguments parsing library in C (compatible with C++).

[![Build Status](https://travis-ci.org/Cofyc/argparse.png)](https://travis-ci.org/Cofyc/argparse)

DESCRIPTION
===========

This module is inspired by parse-options.c (git) and python's argparse
module.

Arguments parsing is common task in cli program, but traditional `getopt`
libraries are not easy to use. This library provides high-level arguments
parsing solutions.

The program defines what arguments it requires, and `argparse` will figure
out how to parse those out of `argc` and `argv`, it also automatically
generates help and usage messages and issues errors when users give the
program invalid arguments.

Features
========

 - handles both optional and positional arguments
 - produces highly informative usage messages
 - issues errors when given invalid arguments

There are basically three types of options:

 - boolean options
 - options with mandatory argument
 - options with optional argument