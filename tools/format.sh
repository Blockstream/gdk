#!/usr/bin/env bash
set -e

clang-format -i src/*.{c,h}pp include/gdk.h
