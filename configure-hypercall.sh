#!/bin/sh

mypath="`readlink -f "$0"`"
mydir="`dirname "$mypath"`"
"$mydir/configure" --target-list=i386-softmmu,x86_64-softmmu --prefix="`dirname "$mydir"`/install"
