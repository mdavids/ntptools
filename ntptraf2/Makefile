#
# Order is important, on Linux LDFLAGS should come last.
#
CC=gcc
CFLAGS += -g -O2 -Wall
LDFLAGS += -lpcap -lncurses -lm

all: ntptraf2

ntptraf2: ntptraf2.c
	$(CC) $(CFLAGS) -o ntptraf2 ntptraf2.c $(LDFLAGS)

clean:
	rm -f ntptraf2
	# Xcode only
	rm -rf ntptraf2.dSYM
