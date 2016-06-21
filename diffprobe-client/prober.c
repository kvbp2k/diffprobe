/*
* Packet replayer/cloner.
  * 
  * November 2008.
  *
 */

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
#include <sys/stat.h>

#include <pcap.h>
#include <pthread.h>

#include "tcpclient.h"
#include "tcpserver.h"
#include "packet.h"
#include "diffprobe.h"
#include "autoconfig.h"

#define PROBER_CONFIG "prober.conf"

/* Global paremeters from config.  */
unsigned int serverip = 0;
unsigned int clientip = 0;
unsigned int A_targetport = 0;
unsigned int P_targetport = 0;
unsigned int localport[2] = {0,0};
int serverMAC[6];
int clientMAC[6];
char device_id[6];

unsigned int verbose = 0;

static unsigned int enc_serverip = 0;  /* For IP encapsulation.  */
static unsigned int enc_clientip = 0;  /* For IP encapsulation.  */
static int ip_encapsulation = 0;   /* Set to 1, if we are over an IPIP tunnel.*/


/* Utility functions.  */

char * ip2str(bpf_u_int32 ip)
{
  struct in_addr ia;

  ia.s_addr = ip;

  return inet_ntoa(ia);
}

unsigned int str2ip(char *ip)
{
  struct in_addr ia;
  int r;
  r = inet_aton(ip, &ia);
  if (r) return ntohl(ia.s_addr);
  return 0;
}

void printMAC(int *MAC)
{
  fprintf(stderr, "%x:%x:%x:%x:%x:%x\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}

void die(char *msg)
{
  fprintf(stderr, "%s\n", msg);
  exit(0);
}

/* Configuration.  */

void prober_config_inspect(void)
{
  fprintf(stderr, "Inspecting Prober Configuration.\n");
  fprintf(stderr, "Server IP: %s (%d)\n", ip2str(serverip), serverip);
  printMAC(serverMAC);
  fprintf(stderr, "Client IP: %s (%d)\n", ip2str(clientip), clientip);
  printMAC(clientMAC);
  fprintf(stderr, "Target Port: %d %d\n", P_targetport, A_targetport);
}


void prober_config_parse_var(char *var)
{
  char *seek;

  seek = (char *) memchr(var, ':', 255);
  seek++;

  if (!strncmp(var, "server", strlen("server")))
    serverip = htonl(str2ip(seek));
  else if (!strncmp(var, "client", strlen("client")))
    clientip = htonl(str2ip(seek));
  else if (!strncmp(var, "enc_server", strlen("enc_server")))
    enc_serverip = htonl(str2ip(seek));
  else if (!strncmp(var, "enc_client", strlen("enc_client")))
    enc_clientip = htonl(str2ip(seek));
  else if (!strncmp(var, "ip_encapsulation", strlen("ip_encapsulation")))
    ip_encapsulation = atoi(seek);
  else if (!strncmp(var, "targetport", strlen("targetport")))
  {
    P_targetport = atoi(seek);
    A_targetport = P_targetport + 1;
  }
  else if (!strncmp(var, "sMAC", strlen("sMAC")))
    sscanf(seek, "%02X,%02X,%02X,%02X,%02X,%02X", 
    &serverMAC[0], &serverMAC[1], &serverMAC[2], &serverMAC[3], &serverMAC[4], &serverMAC[5]);
  else if (!strncmp(var, "cMAC", strlen("cMAC")))
    sscanf(seek, "%02X,%02X,%02X,%02X,%02X,%02X", 
    &clientMAC[0], &clientMAC[1], &clientMAC[2], &clientMAC[3], &clientMAC[4], &clientMAC[5]);
  else if (!strncmp(var, "device", strlen("device")))
    strncpy(device_id, seek, strlen(seek) - 1);

}

int prober_config_load(int argc, char **argv, char *tracefile, int *fileid)
{
  int c = 0;
  opterr = 0;
  int file = -1;

  if(argc == 1)
  {
	fprintf(stderr, "DiffProbe alpha candidate.\n\n");
	fprintf(stderr, "Please specify application.\n");
	fprintf(stderr, "Usage: %s -i <interface> -a <application>\nex. %s -i eth1 -a 1\nApplication choices are:\n1 Skype-1\n2 Skype-2\n3 Vonage-1\n4 Vonage-2\n", 
	  argv[0], argv[0]);
	return -1;
  }

  strncpy(device_id, "-", strlen("-"));
  serverip = htonl(str2ip("143.215.129.100"));

/*FILE *cfg;
  char cfgvar[255];
  if (!(cfg = fopen(PROBER_CONFIG, "r")))
  {
    fprintf(stderr, "Cannot load configuration.");
    return -1;
  }

  while (fgets(cfgvar, sizeof(cfgvar), cfg)) {
    if (cfgvar[0] == '#' || cfgvar[0] == '\n') continue;

    prober_config_parse_var(cfgvar);
  }

#ifdef DEBUG
  prober_config_inspect();
#endif
  fclose(cfg);
*/

  while ((c = getopt (argc, argv, "vhi:a:")) != -1)
  {
  switch (c)
  {
  case 'a':
	  //strncpy(tracefile, optarg, strlen(optarg));
	  *fileid = file = atoi(optarg);
	  if(setfilename(file, tracefile) == -1)
	  {
		  printf("Please specify a valid application.\nChoices are:\n1 Skype-1\n2 Skype-2\n3 Vonage-1\n4 Vonage-2\n");
		  return -1;
	  }
	  break;
  case 'i':
	  strncpy(device_id, optarg, strlen(optarg));
	  break;
  case 'v':
	  verbose = 1;
	  break;
  case '?':
  case ':':
  case 'h':
  default:
	  fprintf(stderr, "DiffProbe alpha candidate.\n\n");
	  if (optopt == 'a' || optopt == 'i')
		  fprintf(stderr, "Option -%c requires an argument.\n", optopt);
	  else if (isprint (optopt))
		  fprintf(stderr, "Unknown option `-%c'.\n", optopt);
//	  else
//		  fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
	  fprintf(stderr, "Usage: %s -i <interface> -a <application>\nex. %s -i eth1 -a 1\nApplication choices are:\n1 Skype-1\n2 Skype-2\n3 Vonage-1\n4 Vonage-2\n", 
			  argv[0], argv[0]);
	  return -1;
  }
  }
  return 0;
}

int prober_autoconfig()
{
	char macaddr[256];
	unsigned int ip;

	memset(macaddr, 0, 256);
	CHKRET(getLocalIP(device_id, &clientip));
	CHKRET(getLocalMAC(device_id, macaddr));
	sscanf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
	&clientMAC[0], &clientMAC[1], &clientMAC[2], &clientMAC[3], &clientMAC[4], &clientMAC[5]);

	memset(macaddr, 0, 256);
	CHKRET(getGatewayAddress(device_id, &ip));
	CHKRET(getMacAddr(ip, device_id, macaddr));
	sscanf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
	&serverMAC[0], &serverMAC[1], &serverMAC[2], &serverMAC[3], &serverMAC[4], &serverMAC[5]);

	return 0;
}

/* Main thing.  */

void prober_device_info(char *dev)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int ret = 0;

  bpf_u_int32 netp;   /* ip          */
  bpf_u_int32 maskp;  /* subnet mask */

  ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

  if(ret == -1) 
    die(errbuf);

  fprintf(stderr, "Device: %s\nIP: %s\n", dev, ip2str(netp));
  fprintf(stderr, "Netmask: %s\n", ip2str(maskp));
}

pcap_t * prober_device_load(char *id)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * device;
  int ret = 0;
  char *dev;

  if(strncmp(device_id, "-", strlen("-")) == 0)
  {
	  dev = pcap_lookupdev(errbuf);
	  if (dev == NULL) {
		  fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		  die(errbuf);
	  }
	  strncpy(device_id, dev, strlen(dev));
  }
  
  device = pcap_open_live(id, 65535, 1, 1, errbuf);
  if (device == NULL)
    die(errbuf);

  ret = pcap_setnonblock(device, 1, errbuf);
  if(ret == -1) fprintf(stderr, "%s\n", errbuf);

  fprintf(stderr, "Using device: %s.\n", id);
  
  return (device);
}

void prober_attach_filter(pcap_t *device)
{
	struct bpf_program fp;		
	bpf_u_int32 g_netp = 0;	/* ip          */
	//bpf_u_int32 g_maskp; 	/* subnet mask */

	/* Build the filter from the configuration file.  */
	char filter[64000];	/* FIXME.  */

	unsigned int fl_entry_sz = sizeof("src host ") + strlen(ip2str(serverip)) + 1;
	snprintf(filter + strlen(filter), fl_entry_sz, "src host %s", ip2str(serverip));

	if (A_targetport > 0)
	{
		sprintf(filter + strlen(filter), " and (port %d", A_targetport);
		sprintf(filter + strlen(filter), " or port %d)", P_targetport);
	}

#ifdef DEBUG
	fprintf(stderr, "FILTER: %s\n", filter);
#endif

	if (pcap_compile(device, &fp, filter, 0, g_netp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(device));
		die("pcap_compile");
	}

	if (pcap_setfilter(device, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(device));
		die("pcap_setfilter");
	}
}

void prober_data_inspect(const u_char *buffer, unsigned int len)
{
  int i;

#ifdef DEBUG
  fprintf(stderr, "Inspecting %d of data.\n", len);
#endif 

  for (i = 0; i < len; i++) {
    if (isprint((int)buffer[i]))
      fprintf(stderr, "%c", buffer[i]);
    else
      fprintf(stderr, ".");
  }
  fprintf(stderr, "\n");
}

void prober_ethernet_inspect(struct ether_header *eth)
{
  fprintf(stderr, "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
}

void prober_udp_inspect(struct ip *iph, struct udphdr *udp)
{
  fprintf(stderr, "UDP (%s:%d - ", inet_ntoa(iph->ip_src), ntohs(udp->uh_sport));
  fprintf(stderr, "%s:%d) l: %d\n", inet_ntoa(iph->ip_dst), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));
}

void prober_tcp_inspect(struct ip *iph, struct tcphdr *tcp)
{
  fprintf(stderr, "TCP (%s:%d - ", inet_ntoa(iph->ip_src), ntohs(tcp->th_sport));
  fprintf(stderr, "%s:%d)\n", inet_ntoa(iph->ip_dst), ntohs(tcp->th_dport));
}

void prober_packet_inspect(struct pcap_pkthdr *hdr, const u_char *packet)
{
  struct ether_header *eth;
  struct ip *iph, *e_iph;
  struct udphdr *udp;
  struct tcphdr *tcp;
  int hdrs_size = 0;

  /* Ethernet.  */
  eth = (struct ether_header *) packet;

#ifdef DEBUG
  prober_ethernet_inspect(eth);
#endif

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  switch(iph->ip_p) {
    case IPPROTO_ICMP:
      fprintf(stderr, "ICMP\n");
      break;
    case IPPROTO_IP:
      e_iph = (struct ip *)(packet + ETHER_HDR_LEN  + 20);
      fprintf(stderr, "IPIP (%s - ", inet_ntoa(e_iph->ip_src));
      fprintf(stderr, "%s)\n", inet_ntoa(e_iph->ip_dst));      
      break;
    case IPPROTO_UDP:
      udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      prober_udp_inspect(iph, udp);
      break;
    case IPPROTO_TCP:
      tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      prober_tcp_inspect(iph, tcp);

      hdrs_size = ETHER_HDR_LEN + (iph->ip_hl << 2) + (tcp->th_off << 2);
      const u_char *payload = (packet + hdrs_size);
      prober_data_inspect(payload, hdr->caplen - hdrs_size);
    break;
    default:
    fprintf(stderr, "IP protocol: %d\n", iph->ip_p);
  }

  fprintf(stderr, "Len: %d CapLen: %d HDRS: %d IP len: %d\n", hdr->len, hdr->caplen, hdrs_size, ntohs(iph->ip_len));
}

void prober_packet_clone(struct pcap_pkthdr *hdr, const u_char *packet, u_char *packet_cloned)
{
  struct ether_header *eth;
  struct ip *iph;
  struct udphdr *udp;
  struct tcphdr *tcp;

  /* All headers (Ethernet, IP and TCP/UDP).  */
  int hdrs_size;

  /* Ethernet.  */
  eth = (struct ether_header *) packet;

  /* IP.  */
  iph = (struct ip *)(packet + ETHER_HDR_LEN);
  switch(iph->ip_p) {
    case IPPROTO_UDP:
      udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      /* FIXME. */
      break;
    case IPPROTO_TCP:
      tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
      hdrs_size = ETHER_HDR_LEN + (iph->ip_hl << 2) + (tcp->th_off << 2);

      //packet_cloned = malloc(hdr->caplen*sizeof(char));
      memcpy(packet_cloned, packet, hdr->caplen);

      //for (int i = 0; i < hdr->caplen - hdrs_size; i++) 
      //  packet_cloned[hdrs_size + i] = '0';     
      memset(packet_cloned + hdrs_size, 0, hdr->caplen - hdrs_size);

      break;
  }
}

#ifdef _IP_ENCAPSULATION_
u_char * prober_ip_encapsulate(const u_char *packet, u_short len)
{
  u_char *ipenc_packet;
  struct ip *iph = malloc(sizeof *iph);
  struct in_addr server, client;
  
  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = htons(len);
  iph->ip_id = 0;
  iph->ip_off = 0;
  iph->ip_ttl = 63;
  iph->ip_p = 4;
  
  server.s_addr = enc_serverip;
  client.s_addr = enc_clientip;
  iph->ip_src = client;
  iph->ip_dst = server;

  /* Recompute checksum.  */
  iph->ip_sum = 0;
  iph->ip_sum = in_cksum((unsigned short *)iph, sizeof(struct ip));

  /* Create new packet.  */
  ipenc_packet = malloc(14 + sizeof(*iph) + len);
  
  /* Attach MAC info.  */
  memcpy(ipenc_packet, packet, 14);
  
  /* Attach IP header.  */
  memcpy(ipenc_packet + 14, iph, sizeof(*iph));
    
  /* Attach encapsulated packet.  */
  memcpy(ipenc_packet + 14 + sizeof(*iph), packet + 14, len - 14);

  return(ipenc_packet);
}
#endif

int getephemeralport(int udpsock)
{
	struct sockaddr_in s;
	int ret = 0;
	unsigned int slen = sizeof(s);
	ret = getsockname(udpsock, (struct sockaddr *)&s, &slen);
	if(ret == -1)
	return 31337;

	return ntohs(s.sin_port);
}

int sendData(int tcpsock, char *filename)
{
	prcvdata pkt;
	struct stat infobuf;
	int ret = 0, len = 0, bytesleft = 0;
	char *buf = NULL;
	FILE *fp;

	if(stat(filename, &infobuf) == -1)
	{
		perror("error: file");
		return -1;
	}
	len = infobuf.st_size;

	printf("\nsending measurement data to server."); fflush(stdout);
	pkt.header.ptype = P_RECVDATA;
	pkt.header.length = 0;
	pkt.datalength = len;
	ret = writewrapper(tcpsock, (char *)&pkt, sizeof(struct _rcvdata));
	if(ret == -1)
	{
		fprintf(stderr, "CLI: error sending data to serv: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	buf = (char *)malloc(len*sizeof(char));
	fp = fopen(filename, "r");
	ret = fread((void *)buf, sizeof(char), len, fp);
	fclose(fp);

	bytesleft = len;
	while(bytesleft > 0)
	{
		int tosend = (bytesleft > 1400) ? 1400 : bytesleft;
		//ret = writewrapper(tcpsock, (char *)buf, len);
		ret = writewrapper(tcpsock, (char *)buf+(len-bytesleft), tosend);
		if(ret == -1)
		{
			fprintf(stderr, "CLI: error sending data to serv: %d\n", tcpsock);
			perror("");
			close(tcpsock);
			free(buf);
			return -1;
		}
		bytesleft -= ret;
	}

	printf(".done.\n");
	free(buf);
	return 0;
}


int main(int argc, char *argv[])
{
  int tcpsock = 0;
  int udpsock = 0, localudpsock[2];
  int udpsock0, udpsock1;
  struct sockaddr_in from;
  double capacityup = 0, capacitydown = 0;
  unsigned int tbresult = 0, tbmindepth = 0, tbmaxdepth = 0, tbabortflag = 0;
  double tbrate = 0, truecapup = 0, truecapdown = 0;
  double sleepRes = 1;
  pcap_t *replayer;
  char filename[256], sndfilename[256], tracefile[256];
  int fileid = -1;
  struct timeval tv;
  struct in_addr sin_addr;

  printf("DiffProbe alpha release. April 2009.\n\n");

  memset(tracefile, 0, 256);
  CHKRET(prober_config_load(argc, argv, tracefile, &fileid));
  replayer = prober_device_load(device_id);
  CHKRET(prober_autoconfig());

  sleepRes = prober_sleep_resolution();
  printf("sleep time resolution: %.2f ms.\n", sleepRes*1000);

  memset(&from, 0, sizeof(from));
  from.sin_family      = AF_INET;
  from.sin_port        = htons(SERV_PORT_UDP);
  from.sin_addr.s_addr = serverip;

  tcpsock = connect2server(serverip, fileid);
  CHKRET(tcpsock);
  udpsock = udpclient(serverip, SERV_PORT_UDP);
  CHKRET(udpsock);
  sin_addr.s_addr = serverip;
  printf("Connected to server %s.\n", inet_ntoa(sin_addr));

  printf("\nEstimating capacity:\n");
  capacityup = estimateCapacity(tcpsock, udpsock, &from);
  CHKRET(capacityup);
  truecapup = capacityup;
  printf("Upstream: %.2f Kbps.\n", capacityup);
  CHKRET(sendCapEst(tcpsock));
  capacitydown = capacityEstimation(tcpsock, udpsock, &from);
  CHKRET(capacitydown);
  truecapdown = capacitydown;
  printf("Downstream: %.2f Kbps.\n", capacitydown);

  printf("\nChecking for traffic shapers:\n");
  tbdetectSender(tcpsock, udpsock, &from, capacityup, sleepRes, 
		  &tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag);
  if(tbresult == 1) truecapup = tbrate;
  printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, tbabortflag, 0);
  tbdetectReceiver(tcpsock, udpsock, capacitydown, sleepRes,
		  &tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag);
  if(tbresult == 1) truecapdown = tbrate;
  printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, tbabortflag, 1);
  close(udpsock);

  localudpsock[0] = prober_bind_port(0);
  CHKRET(localudpsock[0]);
  localport[0] = getephemeralport(localudpsock[0]);
  localudpsock[1] = prober_bind_port(0);
  CHKRET(localudpsock[1]);
  localport[1] = getephemeralport(localudpsock[1]);

  /* Upstream */
  printf("\n *** Upstream *** \n");
  gettimeofday(&tv, NULL);
  sin_addr.s_addr = serverip;
  memset(sndfilename, 0, 256);
  sprintf(sndfilename, "%s_%d.sndts", inet_ntoa(sin_addr), (int)tv.tv_sec);
  upstreamReadPorts(tracefile, &P_targetport, &A_targetport);
  CHKRET(upstreamSendPortList(tcpsock));
  CHKRET(upstreamProber(tcpsock, truecapup/*capacityup*/, 
			  replayer, tracefile, sleepRes, sndfilename));
  CHKRET(sendData(tcpsock, sndfilename));
  printf("Analyzing measurements.\n");
  CHKRET(getDiscResult(tcpsock));

  /* Downstream */
  printf("\n *** Downstream *** \n");
  CHKRET(upstreamRecvPortList(tcpsock, &P_targetport, &A_targetport, 
				  &udpsock0, &udpsock1));
  CHKRET(prober_initrev(tcpsock, replayer, tracefile));
  memset(filename, 0, 256);
  sprintf(filename, "%s_%d.txt", inet_ntoa(sin_addr), (int)tv.tv_sec);
  prober_attach_filter(replayer);
  CHKRET(upstreamReceiver(tcpsock, replayer, filename, 
			  truecapdown/*capacitydown*/, 
			  P_targetport, A_targetport, udpsock0, udpsock1));
  CHKRET(sendData(tcpsock, filename));
  printf("Analyzing measurements.\n");
  CHKRET(getDiscResult(tcpsock));

  close(localudpsock[0]);
  close(localudpsock[1]);
  close(tcpsock);
  pcap_close(replayer);

  printf("\nFor more information, visit: http://www.cc.gatech.edu/~partha/diffprobe\n");

  return(0);
}

