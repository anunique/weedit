#
# Makefile
#
# you ppl cant even imagine how much i hate to write those!
#  btw: greets to my abjects sluts! - CW

SHELL	= /bin/sh
CC	= cc
CFLAGS	= -g -fstack-check -Wall
LIBS	=
TARGET	= weedit
OBJS	= src/crc32.o src/sha1.o src/weedit.o src/io.c src/comparedbs.c src/error.c src/checkdir.c
all:	$(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(LIBS)
	rm -f src/*.o

