#
#

CC = gcc
CFLAGS = -Wall -Wno-parentheses -Wno-deprecated-declarations
#
# LIBS = -lpcap -lgcrypt -lm -lc
LIBS = -lpcap -lm -lc
#
# OBJ = rid_capture.o france.o verify.o nrf_sniffer.o asterix.o export.o opendroneid.o 
OBJ = rid_capture.o france.o export.o opendroneid.o 

all: 	rid_capture

rid_capture: $(OBJ) rid_capture.h opendroneid.h Makefile
	gcc -o rid_capture $(OBJ) $(LIBS)

nrf_sniffer: nrf_sniffer.c
	gcc -o nrf_sniffer nrf_sniffer.c -DSTANDALONE=1 $(CFLAGS) -lc

clean:
	rm *.o
	rm *~

%.o: %.c rid_capture.h
	$(CC) -c -o $@ $< $(CFLAGS)

