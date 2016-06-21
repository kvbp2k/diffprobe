#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>

#define __FAVOR_BSD /* For compilation in Linux.  */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <sys/select.h>
#include <ctype.h>
#include <unistd.h>

#include <pcap.h>
#include <pthread.h>

#include "tcpclient.h"
#include "tcpserver.h"
#include "packet.h"
#include "diffprobe.h"


#define IDLE_PERIOD 5 //s
#define LOAD_PERIOD 10//2 //s
#define LOADDEC_PERIOD 2 //s
//#define GAP_FACTOR  40  // gap decrease

extern unsigned int serverip;
extern unsigned int clientip;
extern unsigned int A_targetport;
extern unsigned int P_targetport;
extern unsigned int localport[2];
extern int serverMAC[6];
extern int clientMAC[6];

extern unsigned int verbose;


inline struct timeval prober_packet_gap(struct timeval y, struct timeval x);
void die(char *msg);
void prober_swait(struct timeval tv, double sleepRes);
//{
  /* Wait for based on select(2). Wait time is given in microsecs.  */
//#if DEBUG
//  fprintf(stderr, "Waiting for %d microseconds.\n", wait_time);
//#endif
//  select(0,NULL,NULL,NULL,&tv); 
//}
void prober_sbusywait(struct timeval tv);
/*inline void prober_sbusywait(struct timeval tv)
{
	struct timeval oldtv, newtv, difftv;
	double diff = 0;
	double maxdiff = tv.tv_sec + tv.tv_usec*1.0e-6;

	gettimeofday(&oldtv, NULL);
	while(1)
	{
		gettimeofday(&newtv, NULL);
		difftv = prober_packet_gap(oldtv, newtv);
		diff += difftv.tv_sec + difftv.tv_usec*1.0e-6;
		if(diff >= maxdiff) return;
		oldtv = newtv;
	}
}*/
double prober_sleep_resolution();

pcap_t * prober_trace_load(char *trace)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *dev;

  dev = pcap_open_offline(trace, errbuf);
  if (dev == NULL) {
    printf("%s\n", errbuf);
    exit(0); //TODO: clean-up
    //return NULL;
  }

  return dev; 
}


unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
  register long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while(nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  if(nbytes == 1)
  {
    oddbyte = 0;
    *((u_char *) &oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return(answer);
}

void prober_packet_mac_adjust(const u_char *packet)
{
  struct ether_header *eth;
  int i = 0;

  eth = (struct ether_header *) packet;
  for(i=0; i < 6; i++)
  {
	  eth->ether_shost[i] = clientMAC[i];
	  eth->ether_dhost[i] = serverMAC[i];
  }
}

void prober_packet_ip_adjust(const u_char *packet)
{
  /*  Attach information from configuration file:
  - server and client IP
    - target port.
  */
  struct ip *iph;

  struct in_addr server, client;

  server.s_addr = serverip;
  client.s_addr = clientip;

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  iph->ip_src = client;
  iph->ip_dst = server;
  iph->ip_ttl = 255;

  /* Recompute checksum.  */
  iph->ip_sum = 0;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ip));
}


void prober_packet_convert2udp(const u_char *packet)
{
  struct ip *iph;
  struct tcphdr *tcp;

  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));

  if(iph->ip_p == 17)
  {
	  int sd = sizeof(double);
	  int su = sizeof(unsigned short);
	  int sc = sizeof(unsigned char);
	  int datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(struct udphdr);
	  if(datalen < sd+su+sc)
		  iph->ip_len = htons(ntohs(iph->ip_len) + sd+su+sc-datalen);
	  return;
  }

  iph->ip_len = htons(ntohs(iph->ip_len) - (tcp->th_off << 2) + sizeof(struct udphdr));
  iph->ip_p = 17;
}

inline void prober_packet_tcp2udp(const u_char *packet, int bzero, int lowport, 
			unsigned short seq, int probingtype, struct timeval ts)
{
  struct ip *iph;
  struct tcphdr *tcp;
  struct udphdr *udp, tudp;

  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
  udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));

  int datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(struct udphdr);
  tudp.uh_sport = htons(localport[lowport]); //tcp->th_sport;
  tudp.uh_ulen = htons(sizeof(struct udphdr) + datalen);
  tudp.uh_sum = 0;

  char buf[2000];
  if(iph->ip_p == 17)
  {
	  if(lowport == 1)
		  tudp.uh_dport = htons(P_targetport);
	  else
		  tudp.uh_dport = htons(A_targetport);
	  memcpy(udp, (const char *)&tudp, sizeof(struct udphdr));
  }
  else if(iph->ip_p == 6)
  {
	  if(lowport == 1)
		  tcp->th_dport = htons(P_targetport);
	  else
		  tcp->th_dport = htons(A_targetport);
	  memcpy(buf, packet + ETHER_HDR_LEN + (iph->ip_hl << 2) + (tcp->th_off << 2), datalen);
	  memcpy((char *)packet + ETHER_HDR_LEN + (iph->ip_hl << 2) + sizeof(struct udphdr), buf, datalen);
	  memcpy(udp, (const char *)&tudp, sizeof(struct udphdr));
  }

  int sd = sizeof(double);
  int su = sizeof(unsigned short);
  int sc = sizeof(unsigned char);
  unsigned char ptype = probingtype;

  if(datalen >= sd+su+sc)
  {
	  //struct timeval ts;
	  //gettimeofday(&ts, NULL);
	  double t = ts.tv_sec + ts.tv_usec / 1000000.0;
	  int dstartoff = ETHER_HDR_LEN + (iph->ip_hl << 2) + sizeof(struct udphdr);

	  if(bzero == 1)
	  memset((char *)packet + dstartoff, 0, datalen);

	  //moved the timestamp to the last 4 bytes (to avoid overwriting app headers)
	  /*memcpy((char *)packet + ETHER_HDR_LEN + (iph->ip_hl << 2) + sizeof(struct udphdr), &t, sizeof(double));
	  if(bzero == 1)
	  memset((char *)packet + ETHER_HDR_LEN + (iph->ip_hl << 2) + sizeof(struct udphdr) + sizeof(double), 
			  0, datalen - 4);*/

	  seq = htons(seq);
	  memcpy((char *)packet + dstartoff + datalen - sd, &t, sd);
	  memcpy((char *)packet + dstartoff + datalen - sd - su, &seq, su);
	  memcpy((char *)packet + dstartoff + datalen - sd - su - sc, /*&probingtype*/&ptype, sc);
  }
  else
	  fprintf(stdout, "too small a packet! : %d\n", datalen);
}

struct pseudo_header
{
	unsigned long s_addr;
	unsigned long d_addr;
	char zer0;
	unsigned char protocol;
	unsigned short length;
};

void prober_packet_transport_adjust(const u_char *packet, u_char *psuedo)
{
  /*  Recompute TCP/UDP checksum.  */
  struct ip *iph;
  struct udphdr *udp;
  struct tcphdr *tcp;
  int datalen, plen;
  struct pseudo_header *ps;

  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  switch(iph->ip_p) {
    case IPPROTO_UDP:
      udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      udp->uh_sum = 0;

      datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(struct udphdr);
      plen = sizeof(struct pseudo_header) + sizeof(struct udphdr) + datalen;
      memset(psuedo, 0, plen);
      ps = (struct pseudo_header *)psuedo;
      ps->protocol = IPPROTO_UDP;
      ps->length = htons(sizeof(struct udphdr) + datalen);
      ps->s_addr = iph->ip_src.s_addr;
      ps->d_addr = iph->ip_dst.s_addr;
      ps->zer0 = 0;
      memcpy(psuedo + sizeof(struct pseudo_header), udp, sizeof(struct udphdr)+datalen);
      udp->uh_sum = in_cksum((unsigned short *)psuedo, plen);
      break;
    case IPPROTO_TCP:
      tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      tcp->th_sum = 0;

      datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcp->th_off << 2);
      plen = sizeof(struct pseudo_header) + (tcp->th_off << 2) + datalen;
      memset(psuedo, 0, plen);
      ps = (struct pseudo_header *)psuedo;
      ps->protocol = IPPROTO_TCP;
      ps->length = htons((tcp->th_off << 2) + datalen);
      ps->s_addr = iph->ip_src.s_addr;
      ps->d_addr = iph->ip_dst.s_addr;
      ps->zer0 = 0;
      memcpy(psuedo + sizeof(struct pseudo_header), tcp, (tcp->th_off << 2)+datalen);
      tcp->th_sum = in_cksum((unsigned short *)psuedo, plen);
  }
}

void prober_packet_classify(const u_char *packet, int app_protocol)
{
  /*  Classify the packet using the TOS field in the  
  IP heaeder.
  */
  struct ip *iph;

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  iph->ip_tos = app_protocol;

  /* Recompute checksum.  */
  iph->ip_sum = 0;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ip));
}

int prober_resize_packet(const u_char *packet, unsigned int sz)
{
	struct ip *iph;
	struct udphdr *udp;
	struct tcphdr *tcp;

	iph = (struct ip *)(packet + ETHER_HDR_LEN);
	switch(iph->ip_p)
	{
		case IPPROTO_UDP:
			udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
			iph->ip_len = htons(sz - ETHER_HDR_LEN);
			udp->uh_ulen = htons(sz - ETHER_HDR_LEN - ntohs(iph->ip_len));
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
			iph->ip_len = htons(sz - ETHER_HDR_LEN);
			/* TODO: calculate TCP checksum? */
			break;
	}

	return 0;
}

double prober_tracerate(char *file)
{
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct timeval start, end, duration;
	unsigned int totsize = 0;
	pcap_t *trace = prober_trace_load(file);

	packet = pcap_next(trace, &hdr);
	end = start = hdr.ts;
	totsize += hdr.caplen;
	while(packet)
	{
		packet = pcap_next(trace, &hdr);
		totsize += hdr.caplen;
		end = hdr.ts;
	}
	pcap_close(trace);

	duration = prober_packet_gap(start, end);
	return (totsize*0.008)/(duration.tv_sec + duration.tv_usec*1.0e-6); //Kbps
}

/*double prober_sleep_resolution()
{
	int i=0;
	struct timeval ts1, ts2, ts;
	double resarr[11] = {1};

	for(i=0; i < 11; i++)
	{
		ts.tv_sec = 0; ts.tv_usec = 10;
		gettimeofday(&ts1, NULL);
		prober_swait(ts);
		gettimeofday(&ts2, NULL);
		ts = prober_packet_gap(ts1, ts2);
		resarr[i] = ts.tv_sec + ts.tv_usec*1.0e-6;
		usleep(10000);
	}

	int compd(const void *a, const void *b);
	qsort((void *)resarr, 11, sizeof(double), compd);

	return resarr[5];
}*/

inline const u_char *prober_pcap_next(pcap_t **trace, 
			struct pcap_pkthdr *hdr, char *tracefile)
{
	const u_char *packet;
       	
	packet = pcap_next(*trace, hdr);
	if(packet)
	return packet;

	pcap_close(*trace);
	*trace = prober_trace_load(tracefile);
	packet = pcap_next(*trace, hdr);
	if(packet)
	return packet;

	return NULL;
}

void prober_sendrev(pcap_t *trace, pcap_t *replayer, int srcport, int dstport)
{
	const u_char *packet;
	struct pcap_pkthdr *hdr = malloc(sizeof *hdr);
	struct ip *iph;
	struct udphdr *udp;
	int datalen = 0;
	u_char *pseudohdr = malloc(2000*sizeof(char));

	packet = pcap_next(trace, hdr);
	prober_packet_mac_adjust(packet);
	prober_packet_convert2udp(packet);
	prober_packet_ip_adjust(packet);
	prober_packet_classify(packet, 0);
	prober_packet_transport_adjust(packet, pseudohdr);

	iph = (struct ip *)(packet + ETHER_HDR_LEN);
	udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
	datalen = ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(struct udphdr);
	udp->uh_sum = 0;
	udp->uh_ulen = htons(sizeof(struct udphdr) + datalen);
	udp->uh_sport = htons(srcport);
	udp->uh_dport = htons(dstport);

	pcap_sendpacket(replayer, packet, hdr->caplen);

	free(hdr);
	free(pseudohdr);
}

int prober_initrev(int tcpsock, pcap_t *replayer, char *file)
{
	pinitrev pkt;
	pinitrevack ackpkt;
	pinitrevdone donepkt;
	pinitrevdoneack doneackpkt;
	int ret = 0;
	pcap_t *trace;

	pkt.header.ptype = P_INITREV;
	pkt.header.length = 0;
	ret = writewrapper(tcpsock, (char *)&pkt, sizeof(struct _initrev));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&ackpkt, sizeof(struct _initrevack));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error reading from server");
		close(tcpsock);
		return -1;
	}
	if(ackpkt.header.ptype != P_INITREV_ACK)
	{
		fprintf(stderr, "CLIENT: wrong packet type!\n");
		close(tcpsock);
		return -1;
	}

	trace = prober_trace_load(file);
	prober_sendrev(trace, replayer, A_targetport, ackpkt.lowport);
	prober_sendrev(trace, replayer, P_targetport, ackpkt.highport);
	pcap_close(trace);

	donepkt.header.ptype = P_INITREV_DONE;
	donepkt.header.length = 0;
	ret = writewrapper(tcpsock, (char *)&donepkt, 
				sizeof(struct _initrevdone));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&doneackpkt, 
				sizeof(struct _initrevdoneack));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error reading from server");
		close(tcpsock);
		return -1;
	}
	if(doneackpkt.header.ptype != P_INITREV_DONE_ACK)
	{
		fprintf(stderr, "CLIENT: wrong packet type!\n");
		close(tcpsock);
		return -1;
	}

	return 0;
}

static pthread_mutex_t cs_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cs_mutex_file = PTHREAD_MUTEX_INITIALIZER;
static int lastpacketsize = 0;

#define RATE_AVG_INTERVAL 0.5 //sliding wnd size in s
static double rateEstimate[2];

void prober_run(pcap_t **trace, pcap_t *replayer, unsigned short *seq,
		double min_packet_gap, char *tracefile, int probingtype, 
		double capacity, int flowtype, FILE *sendtsfp)
{
	const u_char *cappacket;
	struct pcap_pkthdr *hdr = malloc(sizeof *hdr);
	struct pcap_pkthdr *lasthdr = malloc(sizeof *lasthdr);
	struct timeval packet_gap, org_packet_gap;
	struct timeval curtimeold, curtimenew, curtimediff;
	u_char *pseudohdr = malloc(2000*sizeof(char));
	u_char *packet = malloc(2000*sizeof(char));
	int sz = 0, tsz = 0;
	int ret = 0;

	double duration = 0;
	double GAP_FACTOR = 1.0;
	int bzero0 = (flowtype == flowP) ? 1 : 0;
	int loport = (flowtype == flowP) ? 1 : 0;
	int dstport = (loport == 1) ? P_targetport : A_targetport;
	int srcport = localport[loport];

	extern char *sprobetypes[10];
	extern char *sflowtypes[2];

	if(verbose)
	printf("%s-%s ", sprobetypes[probingtype], 
			sflowtypes[flowtype]); fflush(stdout);

	gettimeofday(&curtimeold, NULL);
	cappacket = prober_pcap_next(trace, hdr, tracefile);
	if(cappacket == NULL) pthread_exit((void *)-1);
	sz = hdr->caplen;
	memcpy(packet, cappacket, sz);
	while (cappacket) {
		(*seq)++; //(*seq) <= 65535;

		/* Attach information from configuration file.  */
		prober_packet_mac_adjust(packet);
		prober_packet_convert2udp(packet);
		prober_packet_ip_adjust(packet);
		/* Sets ToS bits and chksum */
		prober_packet_classify(packet, 0);
		/* Modify payload with timestamp (zero the payload:lowport=0) */
		prober_packet_tcp2udp(packet, bzero0, loport, *seq, probingtype, curtimeold);
		/* Re-compute checksums.  */
		prober_packet_transport_adjust(packet, pseudohdr);

#ifdef DEBUG
		prober_packet_inspect(hdr, packet);
#endif
#ifdef _IP_ENCAPSULATION_
		/* Send packet and the cloned one.  */
		if (ip_encapsulation == 1) {
			u_char *ipenc_packet = prober_ip_encapsulate(packet, hdr->caplen);

			pcap_sendpacket(replayer, ipenc_packet, hdr->caplen + 20);
			free(ipenc_packet);  
		}
		else
#endif
		ret = pcap_sendpacket(replayer, packet, sz/*hdr->caplen*/);
		if(ret == -1) pthread_exit((void *)-1);
		memcpy(lasthdr, hdr, sizeof(struct pcap_pkthdr));

		pthread_mutex_lock( &cs_mutex_file );
		fprintf(sendtsfp, "%f %d %s UDP-%d-%d\n", 
			curtimeold.tv_sec+curtimeold.tv_usec*1.0e-6, *seq,
			sprobetypes[probingtype], srcport, dstport);
		pthread_mutex_unlock( &cs_mutex_file );

		cappacket = prober_pcap_next(trace, hdr, tracefile);
		if(cappacket == NULL) pthread_exit((void *)-1);
		sz = hdr->caplen;
		memcpy(packet, cappacket, sz);

		packet_gap = prober_packet_gap(lasthdr->ts, hdr->ts);
		if(packet_gap.tv_sec + packet_gap.tv_usec/1000000.0 > 1) 
		{
			packet_gap.tv_sec = 0;
			packet_gap.tv_usec = 30000;
		}
		org_packet_gap = packet_gap;

		if(probingtype == BLP_A || probingtype == BLP_P || probingtype == BLP_AP)
		{
			if(duration > IDLE_PERIOD)
				break;
		}
		if(probingtype == LIP_P)
		{
			if(flowtype == flowP)
			{
				//printf("I");
				packet_gap.tv_sec /= GAP_FACTOR;
				packet_gap.tv_usec /= GAP_FACTOR;

				pthread_mutex_lock( &cs_mutex );
				tsz = lastpacketsize;
				pthread_mutex_unlock( &cs_mutex );
				if(tsz != 0)
				{
					sz = tsz;
					prober_resize_packet(packet, sz);
				}
			}
			else
			{
				pthread_mutex_lock( &cs_mutex );
				lastpacketsize = sz;
				pthread_mutex_unlock( &cs_mutex );
			}
			if(duration > LOAD_PERIOD)
				break;
		}
		if(probingtype == LIP_A)
		{
			if(flowtype == flowA)
			{
				//printf("I");
				packet_gap.tv_sec /= GAP_FACTOR;
				packet_gap.tv_usec /= GAP_FACTOR;

				pthread_mutex_lock( &cs_mutex );
				tsz = lastpacketsize;
				pthread_mutex_unlock( &cs_mutex );
				if(tsz != 0)
				{
					sz = tsz;
					prober_resize_packet(packet, sz);
				}
			}
			else
			{
				pthread_mutex_lock( &cs_mutex );
				lastpacketsize = sz;
				pthread_mutex_unlock( &cs_mutex );
			}
			if(duration > LOAD_PERIOD)
				break;
		}
		if(probingtype == LIP_AP)
		{
			//printf("I");
			packet_gap.tv_sec /= (GAP_FACTOR/2);
			packet_gap.tv_usec /= (GAP_FACTOR/2);

			if(duration > LOAD_PERIOD)
				break;
		}
		if(probingtype == LDP_A || probingtype == LDP_P || probingtype == LDP_AP)
		{
			//printf("D");
			if(probingtype == LDP_P && flowtype == flowA)
			{
			}
			else
			{
				packet_gap.tv_sec = LOADDEC_PERIOD;
				packet_gap.tv_usec = 0;
			}

			if(duration > LOADDEC_PERIOD)
				break;
		}

		/*  If packet gap is less than min_packet_gap 
		 * we sent the packet immediately. min_packet_gap is in seconds.
		 */
		//printf("."); fflush(stdout);
		if (packet_gap.tv_sec + packet_gap.tv_usec*1.0e-6 >= min_packet_gap)
			prober_swait(packet_gap, min_packet_gap);
		else
			prober_sbusywait(packet_gap);

		/* update duration */
		gettimeofday(&curtimenew, NULL);
		curtimediff = prober_packet_gap(curtimeold, curtimenew);
		//duration += packet_gap.tv_sec + packet_gap.tv_usec/1000000.0;
		duration += curtimediff.tv_sec + curtimediff.tv_usec/1000000.0;
		curtimeold = curtimenew;

		/* update rate estimate (Kbps) of 'non-distorted' version */
		rateEstimate[flowtype] = (rateEstimate[flowtype]*RATE_AVG_INTERVAL + sz*0.008)
		/(org_packet_gap.tv_sec + org_packet_gap.tv_usec*1.0e-6 + RATE_AVG_INTERVAL);
		GAP_FACTOR = capacity*RATE_FACTOR/rateEstimate[flowtype];
		if(GAP_FACTOR < 1) GAP_FACTOR = 1.1;

#ifdef PRINTTRIAL
		printf("%s-%s-%d %f %d diff:%f sleep:%f\n", 
				sprobetypes[probingtype], 
				sflowtypes[flowtype], trial, 
				curtimenew.tv_sec+curtimenew.tv_usec*1.0e-6, sz, 
				curtimediff.tv_sec + curtimediff.tv_usec/1000000.0,
				packet_gap.tv_sec + packet_gap.tv_usec*1.0e-6);
#endif
	}

	free(hdr);
	free(lasthdr);
	free(pseudohdr);
	free(packet);

	printf("."); fflush(stdout);
	pthread_exit((void *)0);
}

struct _p
{
	pcap_t **trace;
	pcap_t *replayer;
	double min_gap;
	int probingtype;
	unsigned short *seq;
	char *tracefile;
	double capacity;
	FILE *sendtsfp;
};
void prober_rA(void *t)
{
	struct _p *p = (struct _p *)t;
	prober_run(p->trace, p->replayer, p->seq, p->min_gap, 
		p->tracefile, p->probingtype, p->capacity, flowA, p->sendtsfp);
}
void prober_rP(void *t)
{
	struct _p *p = (struct _p *)t;
	prober_run(p->trace, p->replayer, p->seq, p->min_gap, 
		p->tracefile, p->probingtype, p->capacity, flowP, p->sendtsfp);
}


int sendDiffProbe(int tcpsock, pcap_t **trace1, pcap_t **trace2, pcap_t *replayer,
		char *tracefile, double capacity, double sleepRes, 
		int probingtype, FILE *sendtsfp)
{
	pprobestart pkt;
	pprobeend pkt2;
	pprobeack ackpkt;
	pthread_t thread1, thread2;
	struct _p p1, p2;
	int ret = 0, threadret = 0;
	unsigned short seqA = -1;
	unsigned short seqP = -1;
	extern char *sprobetypes[10];

	pkt.header.ptype = P_PROBE_START;
	pkt.header.length = 0;
	pkt.probetype = probingtype;
	ret = writewrapper(tcpsock, (char *)&pkt, sizeof(struct _probestart));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&ackpkt, sizeof(struct _probeack));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	if(ackpkt.header.ptype != P_PROBE_ACK)
	{
		fprintf(stderr, "CLIENT: wrong packet type!\n");
		close(tcpsock);
		return -1;
	}

	fprintf(sendtsfp, "%s\n", sprobetypes[probingtype]);

	p1.trace = trace1; p2.trace = trace2;
	p1.replayer = p2.replayer = replayer;
	p1.min_gap = p2.min_gap = sleepRes;
	p1.tracefile = p2.tracefile = tracefile;
	p1.probingtype = p2.probingtype = probingtype;
	p1.seq = &seqA; p2.seq = &seqP;
	p1.capacity = p2.capacity = capacity;
	p1.sendtsfp = p2.sendtsfp = sendtsfp;
	lastpacketsize = 0;

	pthread_create(&thread1, NULL, (void *)prober_rA, (void *)&p1);
	pthread_create(&thread2, NULL, (void *)prober_rP, (void *)&p2);

	pthread_join(thread1, (void **)&threadret);
	CHKRET(threadret);
	pthread_join(thread2, (void **)&threadret);
	CHKRET(threadret);
	if(verbose) printf("\n");
	usleep(100000); //for server to recv pending UDPs

	pkt2.header.ptype = P_PROBE_END;
	pkt2.header.length = 0;
	pkt2.probetype = probingtype;
	ret = writewrapper(tcpsock, (char *)&pkt2, sizeof(struct _probestart));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}

	return 0;
}

int upstreamProber(int tcpsock, double capacityup, pcap_t *replayer, char *file, 
		double sleepRes, char *sendtsfile)
{
	psessionstart pkt;
	psessionack ackpkt;
	pcap_t *trace1, *trace2;
	int ret = 0, trial = 0;
	double tracerate = 0;
	double probingrate = capacityup;
	FILE *sendtsfp = NULL;

	tracerate = prober_tracerate(file); //Kbps
	if(tracerate > capacityup/2)
	{
		fprintf(stderr, "Path capacity low for the given trace. Please try with a lower-rate trace.\n");
		return -1;
	}

	//TODO: we have a running estimate.
	//GAP_FACTOR = (capacityup*0.5)/tracerate;
	//if(GAP_FACTOR < 1) GAP_FACTOR = 1.1;

	trace1 = prober_trace_load(file);
	CHKRETPTR(trace1);
	trace2 = prober_trace_load(file);
	CHKRETPTR(trace2);
	sendtsfp = fopen(sendtsfile, "a");
	CHKRETPTR(sendtsfp);

while(1)
{
	pkt.header.ptype = P_SESSION_START;
	pkt.header.length = 0;
	ret = writewrapper(tcpsock, (char *)&pkt, sizeof(struct _sessionstart));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&ackpkt, sizeof(struct _sessionack));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	if(ackpkt.header.ptype != P_SESSION_ACK)
	{
		fprintf(stderr, "CLIENT: wrong packet type!\n");
		close(tcpsock);
		return -1;
	}
	if(ackpkt.finalflag == 1)
	break;

	probingrate = ackpkt.probingrate;
	if(verbose)
	{
		printf("probing rate: %f\n", probingrate);
	}
	fprintf(sendtsfp, "### TRIAL %d ###\n", trial);
	CHKRET(sendDiffProbe(tcpsock, &trace1, &trace2, replayer, file, 
		probingrate /*capacityup*/, sleepRes, BLP_P, sendtsfp));
	CHKRET(sendDiffProbe(tcpsock, &trace1, &trace2, replayer, file, 
		probingrate /*capacityup*/, sleepRes, LIP_P, sendtsfp));
	CHKRET(sendDiffProbe(tcpsock, &trace1, &trace2, replayer, file, 
		probingrate /*capacityup*/, sleepRes, LDP_P, sendtsfp));

	/*sendDiffProbe(tcpsock, trace1, trace2, replayer, file, capacityup, 
	 * 		sleepRes, BLP_A);
	sendDiffProbe(tcpsock, trace1, trace2, replayer, file, capacityup, 
			sleepRes, LIP_A);
	sendDiffProbe(tcpsock, trace1, trace2, replayer, file, capacityup, 
			sleepRes, LDP_A);
	sendDiffProbe(tcpsock, trace1, trace2, replayer, file, capacityup, 
			sleepRes, BLP_AP);
	sendDiffProbe(tcpsock, trace1, trace2, replayer, file, capacityup, 
			sleepRes, LIP_AP);
	sendDiffProbe(tcpsock, trace1, trace2, replayer, file, capacityup, 
			sleepRes, LDP_AP); */

	trial++;
}

	pcap_close(trace1);
	pcap_close(trace2);
	fclose(sendtsfp);

	return 0;
}


int upstreamSendPortList(int tcpsock)
{
	pportlist portpkt;
	pportlistack portack;
	int ret = 0;

	portpkt.header.ptype = P_PORTLIST;
	portpkt.header.length = 0;
	portpkt.p_port = P_targetport;
	portpkt.n_a_ports = 1;
	portpkt.a_port[0] = A_targetport;
	ret = writewrapper(tcpsock, (char *)&portpkt, 
			sizeof(struct _header)+sizeof(unsigned char)+
			(portpkt.n_a_ports+1)*sizeof(unsigned int));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	ret = readwrapper(tcpsock, (char *)&portack, sizeof(struct _portlistack));
	if(ret == -1)
	{
		fprintf(stderr, "CLIENT: error writing to server");
		close(tcpsock);
		return -1;
	}
	if(portack.header.ptype != P_PORTLIST_ACK)
	{
		fprintf(stderr, "CLIENT: wrong packet type!\n");
		close(tcpsock);
		return -1;
	}

	return 0;
}

int upstreamReadPorts(char *file, unsigned int *p_port, 
			unsigned int *a_port)
{
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ip *iph;
	struct tcphdr *tcp;
	struct udphdr *udp;

	pcap_t *trace = prober_trace_load(file);

	packet = pcap_next(trace, &hdr);
	if(packet)
	{
		iph = (struct ip *)(packet + ETHER_HDR_LEN);
		tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
		udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));

		if(iph->ip_p == 17)
		*a_port = ntohs(udp->uh_dport);
		else if(iph->ip_p == 16)
		*a_port = ntohs(tcp->th_dport);
		else
		{
			fprintf(stderr, "Trace file does not contain TCP/UDP.\n");
			pcap_close(trace);
			return -1;
		}
	}
	else
	{
		fprintf(stderr, "Cannot read trace file.\n");
		return -1;
	}
	pcap_close(trace);

	*p_port = P_PORT;

	return 0;
}


/** BACKUP **/
/*void prober_run_A(pcap_t *trace, pcap_t *replayer, int min_packet_gap)
{
  const u_char *packet;

  struct pcap_pkthdr *hdr = malloc(sizeof *hdr);
  struct pcap_pkthdr *lasthdr = malloc(sizeof *lasthdr);

  struct timeval packet_gap;

  u_char *pseudohdr = malloc(2000*sizeof(char));

  packet = pcap_next(trace, hdr);
  while (packet) {

    // Attach information from configuration file. 
    prober_packet_mac_adjust(packet);
    prober_packet_convert2udp(packet);
    prober_packet_ip_adjust(packet);
#ifdef DEBUG
    prober_packet_inspect(hdr, packet);
#endif

    // Classify packets. 
    prober_packet_classify(packet, kAuthentic);

    // Re-compute checksums.
    prober_packet_transport_adjust(packet, pseudohdr);
    prober_packet_tcp2udp(packet, 0, 0);//1);

    // Send packet and the cloned one.
    if (ip_encapsulation == 1) {
      u_char *ipenc_packet = prober_ip_encapsulate(packet, hdr->caplen);
    
      pcap_sendpacket(replayer, ipenc_packet, hdr->caplen + 20);
      free(ipenc_packet);  
    }
    else
      pcap_sendpacket(replayer, packet, hdr->caplen);

    memcpy(lasthdr, hdr, sizeof(struct pcap_pkthdr));

    packet = pcap_next(trace, hdr);

    packet_gap = prober_packet_gap(lasthdr, hdr);
    if(packet_gap.tv_sec + packet_gap.tv_usec/1000000.0 > 1)
    {
	    packet_gap.tv_sec = 0;
	    packet_gap.tv_usec = 30000;
    }

    //  If packet gap is less than min_packet_gap 
    // we sent the packet immediately. min_packet_gap is in microseconds.  
    printf("."); fflush(stdout);
    if (packet_gap.tv_sec*1000000 + packet_gap.tv_usec > min_packet_gap)
      swait(packet_gap);
  }

  free(hdr);
  free(lasthdr);
  free(pseudohdr);
}*/
/*---------
void prober_run2(pcap_t *trace, pcap_t *replayer, int min_packet_gap)
{
  const u_char *packet;

  struct pcap_pkthdr *hdr = malloc(sizeof *hdr);
  struct pcap_pkthdr *lasthdr = malloc(sizeof *lasthdr);

  struct timeval packet_gap;

  u_char *packet_cloned = malloc(2000*sizeof(char)); //max size
  u_char *pseudohdr = malloc(2000*sizeof(char));

  packet = pcap_next(trace, hdr);
  while (packet) {

    // Attach information from configuration file. 
    prober_packet_mac_adjust(packet);
    prober_packet_convert2udp(packet);
    prober_packet_ip_adjust(packet);
#ifdef DEBUG
    prober_packet_inspect(hdr, packet);
#endif
    prober_packet_clone(hdr, packet, packet_cloned);

    // Classify packets. 
    prober_packet_classify(packet, kAuthentic);
    prober_packet_classify(packet_cloned, kProbe);

    // Re-compute checksums. 
    prober_packet_transport_adjust(packet, pseudohdr);
    prober_packet_tcp2udp(packet);
    prober_packet_transport_adjust(packet_cloned, pseudohdr);
    //prober_packet_tcp2udp(packet_cloned);

    // Send packet and the cloned one. 
    pcap_sendpacket(replayer, packet, hdr->caplen);
    //pcap_sendpacket(replayer, packet_cloned, hdr->caplen);

    memcpy(lasthdr, hdr, sizeof(struct pcap_pkthdr));

    packet = pcap_next(trace, hdr);

    packet_gap = prober_packet_gap(lasthdr, hdr);
    packet_gap.tv_sec *= 20; packet_gap.tv_usec *= 20; //TODO
    if(packet_gap.tv_sec > 1) packet_gap.tv_sec = 1;

    //  If packet gap is less than min_packet_gap 
    // we sent the packet immediately. min_packet_gap is in microseconds.  
    //
    printf("."); fflush(stdout);
    if (packet_gap.tv_sec*1000000 + packet_gap.tv_usec > min_packet_gap)
      swait(packet_gap);
  }

  free(packet_cloned);
  free(hdr);
  free(lasthdr);
  free(pseudohdr);
}
-----*/

