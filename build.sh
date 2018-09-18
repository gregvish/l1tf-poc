#!/bin/bash
gcc -g -D_GNU_SOURCE -std=gnu99 -O0 -o doit doit.c doit.S
gcc -g -o phys phys.c
