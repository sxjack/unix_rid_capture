#
#

CC = gcc
CFLAGS = -Wall -Wno-parentheses -Wno-deprecated-declarations
LIBS = -lpcap -lm -lc

all: 	rid_capture

rid_capture: rid_capture.o rid_capture.h opendroneid.o opendroneid.h Makefile
	gcc -o rid_capture rid_capture.o opendroneid.o $(LIBS)

clean:
	rm *.o
	rm *~

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

