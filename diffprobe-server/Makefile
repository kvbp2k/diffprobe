
CC=gcc

ifeq ($(mode),debug)
	CFLAGS=-c -Wall -DDEBUG -fno-strict-aliasing
else
	CFLAGS=-c -Wall -I/usr/lib/perl/5.10.0/CORE/ -O3 -fno-strict-aliasing
endif
LFLAGS=-L/usr/lib/perl/5.10.0/CORE/

all: clean prober probeserver 

prober: prober.o 
	$(CC) $(LFLAGS) -lm -lpcap -lpthread prober.o wrappers.o tcp_client.o tcpserver.o diffprobe_snd.o diffprobe_rcv.o autoconfig.o tbdetect.o -o prober

prober.o: prober.c
	$(CC) $(CFLAGS) prober.c tcp_client.c tcpserver.c wrappers.c diffprobe_snd.c diffprobe_rcv.c autoconfig.c tbdetect.c

probeserver: probeserver.o
	$(CC) $(LFLAGS) -lm -lpcap -lperl probeserver.o wrappers.o tcpserver.o tcp_client.o analysis.o diffprobe_rcv.o diffprobe_snd.o tbdetect.o -o probeserver

probeserver.o: probeserver.c
	$(CC) $(CFLAGS) -DDSERVER probeserver.c wrappers.c tcpserver.c tcp_client.c analysis.c diffprobe_rcv.c diffprobe_snd.c tbdetect.c

clean:
	rm -rf *.o prober probeserver 
