CFLAGS+= -g -O1 -Wall -Werror
LDFLAGS+= -g

all: example

clean:
	rm -f example *.o

example: example.o hypermem.o

example.o: example.c hypermem.h

hypermem.o: hypermem.c hypermem.h ../include/qemu/hypermem-api.h
