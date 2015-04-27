#!/bin/sh

mypath="`readlink -f "$0"`"
mydir="`dirname "$mypath"`"
#prefixspec=--prefix="`dirname "$mydir"`/install"
"$mydir/configure" --target-list=i386-softmmu,x86_64-softmmu $prefixspec --enable-hypermem --prefix="$mydir/../bin"
make -j4
make install

