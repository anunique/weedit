#
# Makefile
#
# you ppl cant even imagine how much i hate to write those!
#  btw: greets to my abjects sluts! - CW

SHELL	= /bin/sh
CC	= cc
CFLAGS	= -g -fstack-check -Wall -D_FILE_OFFSET_BITS=64
LIBS	=
TARGET	= weedit
OBJS	= src/crc32.o src/sha1.o src/weedit.o src/io.c src/comparedbs.c src/error.c src/checkdir.c src/scandb.c
all:	$(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(LIBS)
	rm -f src/*.o

