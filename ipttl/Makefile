#
# Order is important, on Linux LDFLAGS should come last.
#
CC=gcc
CFLAGS += -g -O2 -Wall
LDFLAGS += -lpcap

all: ipttlplot

ipttlplot: ipttlplot.c
	$(CC) $(CFLAGS) -o ipttlplot ipttlplot.c $(LDFLAGS)

clean:
	rm -f ipttlplot
	# Xcode only
	rm -rf ipttlplot.dSYM
