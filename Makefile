CC=gcc
PRF=-O2
PROFILE=
CFLAGS= -Wall -Werror -g -I.
OBJS= md5.o
LIBS=

all: md5walker

.c.o:
	$(CC) $(CFLAGS) -c $*.c

md5walker: $(OBJS) md5walker.c
	gcc $(CFLAGS) md5walker.c $(OBJS) -o md5walker 

default: md5walker

clean:
	rm md5walker *.o

install: md5walker
	cp md5walker /usr/local/bin
