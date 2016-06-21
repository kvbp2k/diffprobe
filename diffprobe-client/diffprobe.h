#ifndef _DIFFPROBE_H_
#define _DIFFPROBE_H_

#include <pcap.h>

#define VERSION 1
#define RATE_FACTOR 0.9
#define RATE_DROP_FACTOR 2
#define LOSS_RATE_THRESH 0.2

#define SERV_PORT (55001)
#define SERV_PORT_UDP (55001)
#define P_PORT (4321)
#define MAX_NLIPS 1//5

#define LISTENQ (10)
#define TRAIN_LENGTH 50 
#define NITERATIONS 20

#define TBDURATION 60
//#define TB_RATE_AVG_INTERVAL 0.3
#define TB_RATE_LOG_INTERVAL 0.05
#define TB_NPRIOR 3
#define TB_NPOSTERIOR 8
#define TB_NTOTLOSSPOSTERIOR 20
#define TB_RATERATIO 1.10 //1.25
#define TB_LOSSRATE 0.1
#define TB_TOTLOSSRATE 0.01
#define TB_SMOOTH_WINDOW 11
#define TB_SMOOTH_WINDOW_HALF 5
#define TB_SMOOTH_WINDOW_HALF_HALF 2
#define TB_SMOOTH_THRESH TB_RATERATIO
#define TB_MAX_TRAINLEN 5

#define UDPIPHEADERSZ 28

int upstreamProber(int tcpsock, double capacityup, pcap_t *player, char *file, double sleepRes, char *sendtsfile);

int upstreamReceiver(int tcpclientsock, pcap_t *capturer, char *filename, double capacity, unsigned int P_targetport, unsigned int A_targetport, int udpsock0, int udpsock1);

int upstreamReadPorts(char *file, unsigned int *p_port, 
			unsigned int *a_port);

int upstreamRecvPortList(int tcpclientsock, unsigned int *P_target_port, unsigned int *A_target_port, int *udpsock0, int *udpsock1);

int upstreamSendPortList(int tcpsock);

int prober_bind_port(int port);

int prober_initrev(int tcpsock, pcap_t *replayer, char *file);

int server_initrev(int tcpclientsock, int lowport, int highport);

double prober_sleep_resolution();
void prober_swait(struct timeval, double sleepRes);
inline void prober_sbusywait(struct timeval);
struct timeval prober_packet_gap(struct timeval y, struct timeval x);

int tbdetectReceiver(int tcpsock, int udpsock, double capacity, double sleepRes, unsigned int *result, unsigned int *minbktdepth, unsigned int *maxbktdepth, double *tbrate, unsigned int *abortflag);
int tbdetectSender(int tcpsock, int udpsock, struct sockaddr_in *from, double capacity, double sleepRes, unsigned int *result, unsigned int *minbktdepth, unsigned int *maxbktdepth, double *tbrate, unsigned int *abortflag);
void printShaperResult(unsigned int tbresult, unsigned int tbmindepth, unsigned int tbmaxdepth, double tbrate, unsigned int tbabortflag, int dir);


#define CHKRET(a) if(a != -1); \
	else return -1
#define CHKRETPTR(a) if(a != NULL); \
	else return -1

#endif

