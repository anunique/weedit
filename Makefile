#
# Makefile
#
# you ppl cant even imagine how much i hate to write those!
#  btw: greets to my abjects sluts! - CW

SHELL	= /bin/sh
CC	= gcc
CFLAGS	= -g -fstack-check
LIBS	=
TARGET	= weedit
OBJS	= crc32.o sha1.o md5.o weedit.o
all:	$(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(LIBS)
	rm -f *.o

