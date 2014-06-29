CFLAGS+= -g -O1 -Wall -Werror -m32
LDFLAGS+= -g -m32

all: example

clean:
	rm -f example *.o

example: example.o qhyper.o

example.o: example.c qhyper.h

qhyper.o: qhyper.c qhyper.h ../include/qemu/hypercall-api.h
