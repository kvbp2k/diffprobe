/*
 * Packet capturer.
 * 
 * November 2008.
 *
 */

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

#define PROBESERVER_CONFIG "probeserver.conf"
#define PROBESERVER_MAX_CLIENTS 1024

/* Global parameters from config.  */
static unsigned int probe_clients[PROBESERVER_MAX_CLIENTS];
static unsigned int n_clients = 0;

unsigned int serverip = 0;
unsigned int clientip = 0;
unsigned int A_targetport = 0;
unsigned int P_targetport = 0;
unsigned int localport[2] = {0,0};
int serverMAC[6];
int clientMAC[6];

unsigned int verbose = 1;


/* Utility functions.  */

void swaittv(int wait_time)
{
	/* Wait for based on select(2). Wait time is given in microsecs.  */
	struct timeval tv;
	tv.tv_sec = 0;   
	tv.tv_usec = wait_time;  

#if DEBUG
	fprintf(stderr, "Waiting for %d microseconds.\n", wait_time);
#endif

	select(0,NULL,NULL,NULL,&tv);	
}

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

void die(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(0);
}

/* Configuration.  */

void prober_config_inspect(void)
{
	int i;

	fprintf(stderr, "Inspecting Probe Server Configuration.\n");
	for (i = 0; i < n_clients; i++)
		fprintf(stderr, "Accepting from Client IP: %s (%d)\n", ip2str(probe_clients[i]), probe_clients[i]);
}


void prober_config_parse_var(char *var)
{
	char *seek;

	seek = (char *) memchr(var, ':', 255);
	seek++;

	if (!strncmp(var, "client", strlen("client")))
		probe_clients[n_clients++] = htonl(str2ip(seek));
	else if (!strncmp(var, "port", strlen("port")))
	{
		P_targetport = atoi(seek);
		A_targetport = P_targetport + 1;
	}
	else if (!strncmp(var, "server", strlen("server")))
		clientip = htonl(str2ip(seek));
	else if (!strncmp(var, "cMAC", strlen("sMAC")))
		sscanf(seek, "%02X,%02X,%02X,%02X,%02X,%02X", 
		&serverMAC[0], &serverMAC[1], &serverMAC[2], &serverMAC[3], &serverMAC[4], &serverMAC[5]);
	else if (!strncmp(var, "sMAC", strlen("cMAC")))
		sscanf(seek, "%02X,%02X,%02X,%02X,%02X,%02X", 
		&clientMAC[0], &clientMAC[1], &clientMAC[2], &clientMAC[3], &clientMAC[4], &clientMAC[5]);
}

void prober_config_load(void)
{
	FILE *cfg;
	char cfgvar[255];

	if (!(cfg = fopen(PROBESERVER_CONFIG, "r")))
        die("Cannot load configuration.");

    while (fgets(cfgvar, sizeof(cfgvar), cfg)) {
        if (cfgvar[0] == '#' || cfgvar[0] == '\n') continue;

        prober_config_parse_var(cfgvar);
    }

#ifdef DEBUG
	prober_config_inspect();
#endif
    fclose(cfg);
}


/* Main thing.  */

void prober_device_info(char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret = 0;

	bpf_u_int32 netp; 	/* ip          */
	bpf_u_int32 maskp; 	/* subnet mask */
	
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

  	if(ret == -1) {
   		printf("%s\n", errbuf);
   		exit(1);
  	}


	fprintf(stderr, "Device: %s\nIP: %s\n", dev, ip2str(netp));
	fprintf(stderr, "Netmask: %s\n", ip2str(maskp));
}

pcap_t * prober_device_load(void)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcapt;
	int ret = 0;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		die(errbuf);
	}

#ifdef DEBUG
	prober_device_info(dev);
#endif

 	pcapt = pcap_open_live(dev, 65535, 1, 1, errbuf);
	if(pcapt == NULL) return pcapt;

	ret = pcap_setnonblock(pcapt, 1, errbuf);
	if(ret == -1) die(errbuf);

	return pcapt;
}

int prober_attach_filter(pcap_t *device, char *clientip)
{
	struct bpf_program fp;		
	bpf_u_int32 g_netp = 0; 	/* ip          */
	//bpf_u_int32 g_maskp; 	/* subnet mask */

	/* Build the filter from the configuration file.  */
	char filter[64000];	/* FIXME.  */

	/*for (i = 0; i < n_clients; i++) {
		unsigned int fl_entry_sz = sizeof("src host ") + strlen(ip2str(probe_clients[i])) + 1;

		snprintf(filter + strlen(filter), fl_entry_sz, "src host %s", ip2str(probe_clients[i]));

		if (i + 1 < n_clients) 
			strncpy(filter + strlen(filter), " or ", 4);

	}*/

	unsigned int fl_entry_sz = sizeof("src host ") + strlen(clientip) + 1;
	snprintf(filter + strlen(filter), fl_entry_sz, "src host %s", clientip);

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
		fprintf(stderr, "pcap_compile");
		return -1;
	}

	if (pcap_setfilter(device, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(device));
		return -1;
	}

	return 0;
}

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

int recvData(int tcpclientsock, char *filename, int direction /*0 up 1 down*/)
{
	prcvdata pkt;
	int ret = 0, len = 0, bytesleft = 0;
	char *buf;
	FILE *fp;

	ret = readwrapper(tcpclientsock, (char *)&pkt, sizeof(struct _rcvdata));
	if(ret == -1)
	{
		perror("SERV: error reading from client.\n");
		close(tcpclientsock);
		return -1;
	}
	if(pkt.header.ptype != P_RECVDATA)
	{
		fprintf(stderr, "SERV: wrong packet type: %d\n", pkt.header.ptype);
		return -1;
	}

	len = pkt.datalength;
	buf = (char *)malloc(len*sizeof(char));
	/*ret = readwrapper(tcpclientsock, (char *)&buf, len*sizeof(char));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error reading from client..\n");
		perror("");
		close(tcpclientsock);
		free(buf);
		return -1;
	}*/
	bytesleft = len;
	while(bytesleft > 0)
	{
		int torecv = (bytesleft > 1400) ? 1400 : bytesleft;
		ret = readwrapper(tcpclientsock, (char *)buf+(len-bytesleft), torecv);
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error reading data from client..\n");
			perror("");
			close(tcpclientsock);
			free(buf);
			return -1;
		}
		bytesleft -= ret;
	}

	fp = fopen(filename, "a");
	if(direction == 1)
	fprintf(fp, "### DOWNSTREAM ###\n");
	ret = fwrite((void *)buf, sizeof(char), len, fp);
	fclose(fp);
	free(buf);

	return 0;
}


int main(int argc, char *argv[], char **env)
{
	int tcpsock, tcpclientsock;
	int udpsockcap, udpsockeph[2];
	int udpsock0, udpsock1;
	double upcap = 0, downcap = 0;
	unsigned int tbresult = 0, 
		tbmindepth = 0, tbmaxdepth = 0, tbabortflag = 0;
	double tbrate = 0, trueupcap = 0, truedowncap = 0;
	double sleepRes = 1;
	pcap_t *capturer;
	struct sockaddr_in saddr;
	unsigned int ssz = sizeof(saddr);
	char tracefile[256], filename[256], sndfilename[256];
	struct timeval tv;
	struct sockaddr_in from;

	memset(tracefile, 0, 256);

	initperl(env);

	prober_config_load(); 

	tcpsock = create_server();

	capturer = prober_device_load();

	sleepRes = prober_sleep_resolution();
	printf("sleep time resolution: %.2f ms.\n", sleepRes*1000);

while(1)
{
	printf("Waiting for new clients..\n");

	udpsockcap = prober_bind_port(SERV_PORT_UDP);
	CHKRET(udpsockcap);

	tcpclientsock = handle_clients(tcpsock, udpsockcap);
	CHKRET(tcpclientsock);
	close(tcpsock);
	if(getpeername(tcpclientsock, (struct sockaddr *)&saddr, &ssz) == -1)
	fprintf(stderr, "cannot get peer address\n");
	gettimeofday(&tv, NULL);
	memset(filename, 0, 256);
	sprintf(filename, "%s_%d.txt", inet_ntoa(saddr.sin_addr), (int)tv.tv_sec);
	memset(sndfilename, 0, 256);
	sprintf(sndfilename, "%s_%d.sndts", 
			inet_ntoa(saddr.sin_addr), (int)tv.tv_sec);
	printf("Probing from %s\n", inet_ntoa(saddr.sin_addr));

	printf("\nEstimating capacity:\n");
	CHKRET(preprocess_newclient(tcpclientsock, udpsockcap, 
					&upcap, &downcap, &from, tracefile));
	trueupcap = upcap; truedowncap = downcap;
	printf("upstream capacity: %.2f Kbps.\n", upcap);
	printf("downstream capacity: %.2f Kbps.\n", downcap);

	printf("Checking for traffic shapers:\n");
	tbdetectReceiver(tcpclientsock, udpsockcap, upcap, sleepRes,
		&tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag);
	if(tbresult == 1) trueupcap = tbrate;
	printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, tbabortflag, 0);
	tbdetectSender(tcpclientsock, udpsockcap, &from, downcap, sleepRes,
		&tbresult, &tbmindepth, &tbmaxdepth, &tbrate, &tbabortflag);
	if(tbresult == 1) truedowncap = tbrate;
	printShaperResult(tbresult, tbmindepth, tbmaxdepth, tbrate, tbabortflag, 1);


	printf("\n *** Upstream *** \n");
	CHKRET(upstreamRecvPortList(tcpclientsock, &P_targetport, &A_targetport,
					&udpsock0, &udpsock1));
	CHKRET(prober_attach_filter(capturer, inet_ntoa(saddr.sin_addr)));
	CHKRET(upstreamReceiver(tcpclientsock, capturer, filename, 
				trueupcap/*upcap*/, P_targetport, A_targetport,
				udpsock0, udpsock1));
	CHKRET(recvData(tcpclientsock, sndfilename, 0));
	CHKRET(postprocess_client(tcpclientsock, filename, sndfilename, 0, env));

	printf("\n *** Downstream *** \n");
	udpsockeph[0] = prober_bind_port(0);
	CHKRET(udpsockeph[0]);
	localport[0] = getephemeralport(udpsockeph[0]);
	udpsockeph[1] = prober_bind_port(0);
	CHKRET(udpsockeph[1]);
	localport[1] = getephemeralport(udpsockeph[1]);
	FILE *sendtsfp = fopen(sndfilename, "a");
	CHKRETPTR(sendtsfp);
	fprintf(sendtsfp, "### DOWNSTREAM ###\n");
	fclose(sendtsfp);

	upstreamReadPorts(tracefile, &P_targetport, &A_targetport);
	CHKRET(upstreamSendPortList(tcpclientsock));
	server_initrev(tcpclientsock, localport[0], localport[1]);
	serverip = saddr.sin_addr.s_addr;
	CHKRET(upstreamProber(tcpclientsock, truedowncap/*downcap*/, capturer, 
				tracefile, sleepRes, sndfilename));
	CHKRET(recvData(tcpclientsock, filename, 1));
	CHKRET(postprocess_client(tcpclientsock, filename, sndfilename, 1, env));

	close(udpsockcap);
	close(udpsockeph[0]);
	close(udpsockeph[1]);
	close(tcpclientsock);

	break;
}

	endperl();
	pcap_close(capturer);

	return(0);
}

