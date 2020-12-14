#!/bin/bash

. tap-functions
plan_no_plan

is "$(./test_argparse -f --path=/path/to/file a 2>&1)" 'force: 1
path: /path/to/file
argc: 1
argv[0]: a'

is "$(./test_argparse -f -f --force --no-force 2>&1)" 'force: 2'

is "$(./test_argparse -n 2>&1)" 'error: option `-n