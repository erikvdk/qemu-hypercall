CFLAGS+= -g -O1 -Wall -Werror -m32
LDFLAGS+= -g -m32

all: example

clean:
	rm -f example *.o

example: example.o hypermem.o

example.o: example.c hypermem.h

hypermem.o: hypermem.c hypermem.h ../include/qemu/hypermem-api.h
