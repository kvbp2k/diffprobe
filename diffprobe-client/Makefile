
CC=gcc

ifeq ($(mode),debug)
	CFLAGS=-c -Wall -DDEBUG -fno-strict-aliasing
else
	CFLAGS=-c -Wall -O3 -fno-strict-aliasing
endif
LFLAGS=

all: clean prober

prober: prober.o 
	$(CC) $(LFLAGS) -lm -lpcap -lpthread prober.o wrappers.o tcp_client.o tcpserver.o diffprobe_snd.o diffprobe_rcv.o autoconfig.o tbdetect.o -o prober

prober.o: prober.c
	$(CC) $(CFLAGS) prober.c tcp_client.c tcpserver.c wrappers.c diffprobe_snd.c diffprobe_rcv.c autoconfig.c tbdetect.c

clean:
	rm -rf *.o prober
