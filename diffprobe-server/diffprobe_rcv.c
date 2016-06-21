#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#define __FAVOR_BSD	/* For compilation in Linux.  */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <ctype.h>
#include <unistd.h>

#include <pcap.h>

#include "tcpserver.h"
#include "packet.h"
#include "analysis.h"
#include "diffprobe.h"

extern unsigned int verbose;


int prober_bind_port(int port)
{
	int sock;
	struct sockaddr_in echoserver;

	sock = socket(PF_INET, SOCK_DGRAM/*SOCK_STREAM*//*SOCK_RAW*/, IPPROTO_UDP);
	if(sock == -1)
	{
		fprintf(stderr, "couldn't creat socket");
		return -1;
	}

	memset(&echoserver, 0, sizeof(echoserver));
	echoserver.sin_family = AF_INET;
	echoserver.sin_addr.s_addr = htonl(INADDR_ANY);
	echoserver.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &echoserver,	sizeof(echoserver)) < 0)
	{
		fprintf(stderr, "Failed to bind the server socket");
		return -1;
	}
	//if (listen(sock, 10) < 0) {
	//	fprintf(stderr, "Failed to listen on server socket");
	//}

	return sock;
}

void prober_packet_log(struct pcap_pkthdr *hdr, const u_char *packet, FILE *fp,
			unsigned short *curseq, unsigned char *curprobingtype,
			int *curport)
{
	struct ether_header *eth;
	struct ip *iph;
	struct udphdr *udp;
	struct tcphdr *tcp;

	/*int i=0;
	for(i=0;i<100;i++)
	printf("%x ", packet[i]);
	printf("\n");
	printf("captured %d tot %d\n", hdr->caplen, hdr->len);*/

	/* Ethernet.  */
	eth = (struct ether_header *) packet;

	/* IP.  */
	iph = (struct ip *)(packet + ETHER_HDR_LEN);
	double t = hdr->ts.tv_sec + hdr->ts.tv_usec/1000000.0;
	double tt = -1;
	double owd = -1;
	int datalen = 0;
	unsigned short seq = 0;
	unsigned char probingtype = 9;
	extern char *sprobetypes[10];

	switch(iph->ip_p) {
		case IPPROTO_UDP:
			datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(struct udphdr);
			udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
			if(datalen >= 7)
			{
				tt = *(double *)((char *)udp + sizeof(struct udphdr) + 
						datalen - sizeof(double));
				owd = 1000*(t - tt);
				seq = *(unsigned short *)((char *)udp + sizeof(struct udphdr) + 
						datalen - sizeof(double) - sizeof(unsigned short));
				seq = ntohs(seq);
				probingtype = *(unsigned char *)((char *)udp + sizeof(struct udphdr) + 
						datalen - sizeof(double) - sizeof(unsigned short) - sizeof(unsigned char));
			}

			fprintf(fp, "%lf %lf %u %s UDP-%s-%d-", tt, owd, seq, sprobetypes[probingtype], 
					inet_ntoa(iph->ip_src), ntohs(udp->uh_sport));
			fprintf(fp, "%s-%d\n", inet_ntoa(iph->ip_dst), ntohs(udp->uh_dport));

			*curseq = seq;
			*curprobingtype = probingtype;
			*curport = ntohs(udp->uh_dport);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
			fprintf(fp, "%ld %d,TCP-%s-%d-", hdr->ts.tv_sec, (int)hdr->ts.tv_usec, inet_ntoa(iph->ip_src), ntohs(tcp->th_sport));
			fprintf(fp, "%s-%d,%d\n", inet_ntoa(iph->ip_dst), ntohs(tcp->th_dport), ntohs(iph->ip_len));
			break;
		default:
			fprintf(stderr, "UNKNOWN IP type.\n");
	}
}

int server_initrev(int tcpclientsock, int lowport, int highport)
{
	pinitrev pkt;
	pinitrevack ackpkt;
	pinitrevdone donepkt;
	pinitrevdoneack doneackpkt;
	int ret = 0;

	ret = readwrapper(tcpclientsock, (char *)&pkt, sizeof(struct _initrev));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading.");
		close(tcpclientsock);
		return -1;
	}
	if(pkt.header.ptype != P_INITREV)
	{
		fprintf(stderr, "SERV: wrong packet type! (initrev)\n");
		close(tcpclientsock);
		return -1;
	}
	ackpkt.header.ptype = P_INITREV_ACK;
	ackpkt.header.length = 0;
	ackpkt.lowport = lowport;
	ackpkt.highport = highport;
	ret = writewrapper(tcpclientsock, (char *)&ackpkt, 
			sizeof(struct _initrevack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing.");
		close(tcpclientsock);
		return -1;
	}

	ret = readwrapper(tcpclientsock, (char *)&donepkt, 
				sizeof(struct _initrevdone));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading.");
		close(tcpclientsock);
		return -1;
	}
	if(donepkt.header.ptype != P_INITREV_DONE)
	{
		fprintf(stderr, "SERV: wrong packet type! (initrev done)\n");
		close(tcpclientsock);
		return -1;
	}
	doneackpkt.header.ptype = P_INITREV_DONE_ACK;
	doneackpkt.header.length = 0;
	ret = writewrapper(tcpclientsock, (char *)&doneackpkt, 
				sizeof(struct _initrevdoneack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing.");
		close(tcpclientsock);
		return -1;
	}

	return 0;
}

int prober_capture_start(int tcpclientsock, pcap_t *capturer, int probetype, FILE *fp,
			 int P_targetport, int *lostpackets, int *totalpackets)
{
	const u_char *packet;
	struct pcap_pkthdr *hdr = malloc(sizeof *hdr);
	fd_set readset;
	int maxfd = tcpclientsock+1;
	struct timeval tout;
	pprobeend pkt;
	int ret = 0;
	extern char *sprobetypes[10];
	unsigned short seq = 0, lastseq = 0;
	unsigned short minseq = 65535, maxseq = 0;
	unsigned char probingtype = 9;
	int port = 0, trueseq = 0;
	int totpackets = 0, seqcarryover = 0;
	*lostpackets = *totalpackets = 0;

	preprocess_newclient(tcpclientsock, 0, NULL, NULL, NULL, NULL);
	if(verbose) printf("%s ", sprobetypes[probetype]);
	printf("."); fflush(stdout);
	fprintf(fp, "%s\n", sprobetypes[probetype]);

	while (1) {
		packet = pcap_next(capturer, hdr);
		if (packet)
		{
			probingtype = 255;
			prober_packet_log(hdr, packet, fp,
					&seq, &probingtype, &port);
			//loss computation
			if(probingtype == probetype && 
			   port == P_targetport) // P-flow
			{
				if(lastseq - seq > 30000) // wrap-around
				seqcarryover++;
				lastseq = seq;

				trueseq = seq + 65535*seqcarryover + 1;
				minseq = (minseq > trueseq) ? trueseq : minseq;
				maxseq = (maxseq < trueseq) ? trueseq : maxseq;
				totpackets++;
			}
		}

		FD_ZERO(&readset);
		FD_SET(tcpclientsock, &readset);
		tout.tv_sec = 0; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			free(hdr);
			return -1;
		}
		else if(ret == 0) //timeout
		{
		}
		else
		{
			if(FD_ISSET(tcpclientsock, &readset))
			{
				ret = readwrapper(tcpclientsock, (char *)&pkt, 
						sizeof(struct _probestart));
				if(ret == -1 || pkt.header.ptype != P_PROBE_END)
				{
					fprintf(stderr, "SERV: error reading or wrong packet type.\n");
					close(tcpclientsock);
					free(hdr);
					return -1;
				}
				break;
			}
		}
	}

	*totalpackets = 1 + (maxseq - minseq);
	*lostpackets = *totalpackets - totpackets;

	free(hdr);
	fflush(fp);
	printf("."); fflush(stdout);

	return 0;
}

int upstreamRecvPortList(int tcpclientsock, unsigned int *P_target_port, 
			unsigned int *A_target_port, int *udpsock0, int *udpsock1)
{
	pportlist portpkt;
	pportlistack portack;
	int ret = 0;

	int cursz = sizeof(struct _header)+sizeof(unsigned int)+
			sizeof(unsigned char);
	ret = readwrapper(tcpclientsock, (char *)&portpkt, cursz);
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client");
		close(tcpclientsock);
		return -1;
	}
	ret = readwrapper(tcpclientsock, (char *)&portpkt+cursz, 
			portpkt.n_a_ports*sizeof(unsigned int));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client");
		close(tcpclientsock);
		return -1;
	}
	if(portpkt.header.ptype != P_PORTLIST)
	{
		fprintf(stderr, "SERV: wrong packet type!\n");
		close(tcpclientsock);
		return -1;
	}
	*P_target_port = portpkt.p_port;
	*A_target_port = portpkt.a_port[0];

	*udpsock0 = prober_bind_port(*P_target_port);
	CHKRET(*udpsock0);
	*udpsock1 = prober_bind_port(*A_target_port);
	CHKRET(*udpsock1);

	portack.header.ptype = P_PORTLIST_ACK;
	portack.header.length = 0;
	portack.status = 1;
	ret = writewrapper(tcpclientsock, (char *)&portack,
			sizeof(struct _portlistack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing to client");
		close(tcpclientsock);
		close(*udpsock0);
		close(*udpsock1);
		return -1;
	}

	return 0;
}

int upstreamReceiver(int tcpclientsock, pcap_t *capturer, char *filename, 
		double capacity, unsigned int P_target_port, 
		unsigned int A_target_port, int udpsock0, int udpsock1)
{
	psessionstart pkt;
	psessionack ackpkt;
	FILE *fp;
	int i = 0, ret = 0;
	int totsent = 0, totlost = 0;
	double sessionlossrate = 0;
	double probingrate = capacity;
	unsigned char discardflag = 0;

	fp = fopen(filename, "w");

for(i = 0; i < MAX_NLIPS; i++)
{
	ret = readwrapper(tcpclientsock, (char *)&pkt, 
			sizeof(struct _sessionstart));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client");
		close(tcpclientsock);
		fclose(fp);
		close(udpsock0);
		close(udpsock1);
		return -1;
	}
	if(pkt.header.ptype != P_SESSION_START)
	{
		fprintf(stderr, "SERV: wrong packet type!\n");
		close(tcpclientsock);
		fclose(fp);
		close(udpsock0);
		close(udpsock1);
		return -1;
	}
	ackpkt.header.ptype = P_SESSION_ACK;
	ackpkt.header.length = 0;
	ackpkt.finalflag = 0;
	ackpkt.probingrate = probingrate;
	ackpkt.discardflag = discardflag;
	ret = writewrapper(tcpclientsock, (char *)&ackpkt, 
			sizeof(struct _sessionack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing to client");
		close(tcpclientsock);
		fclose(fp);
		close(udpsock0);
		close(udpsock1);
		return -1;
	}

	fprintf(fp, "### TRIAL %d ###\n", i);
	CHKRET(prober_capture_start(tcpclientsock, capturer, BLP_P, fp,
					P_target_port, &totlost, &totsent));
	CHKRET(prober_capture_start(tcpclientsock, capturer, LIP_P, fp,
					P_target_port, &totlost, &totsent));
	sessionlossrate = 1.0*totlost/totsent;
	if(verbose)
	printf("lost %d sent: %d\n", totlost,totsent);
	CHKRET(prober_capture_start(tcpclientsock, capturer, LDP_P, fp,
					P_target_port, &totsent, &totlost));

	/*prober_capture_start(tcpclientsock, capturer, BLP_A, fp);
	prober_capture_start(tcpclientsock, capturer, LIP_A, fp);
	prober_capture_start(tcpclientsock, capturer, LDP_A, fp);

	prober_capture_start(tcpclientsock, capturer, BLP_AP, fp);
	prober_capture_start(tcpclientsock, capturer, LIP_AP, fp);
	prober_capture_start(tcpclientsock, capturer, LDP_AP, fp);*/

	// Adaptive probing rate
	if(sessionlossrate > LOSS_RATE_THRESH)
	{
		probingrate /= RATE_DROP_FACTOR;
		discardflag = 1;
	}
	else
	{
		discardflag = 0;
	}
}

	ret = readwrapper(tcpclientsock, (char *)&pkt, 
			sizeof(struct _sessionstart));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client");
		close(tcpclientsock);
		fclose(fp);
		close(udpsock0);
		close(udpsock1);
		return -1;
	}
	if(pkt.header.ptype != P_SESSION_START)
	{
		fprintf(stderr, "SERV: wrong packet type!\n");
		close(tcpclientsock);
		fclose(fp);
		close(udpsock0);
		close(udpsock1);
		return -1;
	}
	ackpkt.header.ptype = P_SESSION_ACK;
	ackpkt.header.length = 0;
	ackpkt.finalflag = 1;
	ret = writewrapper(tcpclientsock, (char *)&ackpkt, 
			sizeof(struct _sessionack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing to client");
		close(tcpclientsock);
		fclose(fp);
		close(udpsock0);
		close(udpsock1);
		return -1;
	}

	fclose(fp);
	close(udpsock0);
	close(udpsock1);

	return 0;
}

