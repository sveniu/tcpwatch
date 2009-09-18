CC=gcc
prog = tcpwatch

all:
	$(CC) -g -W -Wall -lpcap -o $(prog) $(prog).c

clean:
	rm -f $(prog) *.o
