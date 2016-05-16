#!/bin/bash

mkdir log
mkdir pid
gcc -g -Wall syscall_def.c sandbox.c fuzzer.c -o  fuzzer
