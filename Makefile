CC=gcc
prog = tcpwatch

all:
	$(CC) -g -W -Wall -lpcap -lrt -o $(prog) $(prog).c

clean:
	rm -f $(prog) *.o
