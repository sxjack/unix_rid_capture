#
#

CC = gcc
CFLAGS = -Wall -Wno-parentheses -Wno-deprecated-declarations
LIBS = -lpcap -lm -lc
OBJ = rid_capture.o france.o opendroneid.o 

all: 	rid_capture

rid_capture: $(OBJ) rid_capture.h opendroneid.h Makefile
	gcc -o rid_capture $(OBJ) $(LIBS)

clean:
	rm *.o
	rm *~

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

