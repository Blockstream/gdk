#!/usr/bin/env bash
set -e

pvs-studio-analyzer analyze -o $1/gdk.log -j 4
plog-converter -a GA:1,2 -t tasklist -o $1/gdk.tasks $1/gdk.log
