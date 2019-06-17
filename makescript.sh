#!/bin/bash

make clean
cp ./src/Makefile.am.old ./src/Makefile.am
make
cp ./src/Makefile.am.new ./src/Makefile.am
make