#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "packet.h"
#include "tcpserver.h"
#include "tcpclient.h"
#include "analysis.h"
#include "diffprobe.h"

extern unsigned int verbose;


int create_server()
{
	int list_s;
	short int port = SERV_PORT;
	struct sockaddr_in servaddr;
	int optval = 1;
	int ret = 0;
	int sndsize = 1024*1024;

	if ( (list_s = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) 
	{
		fprintf(stderr, "SERV: Error creating listening socket.\n");
		exit(-1);
	}

	optval = 1;
	setsockopt(list_s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	ret = setsockopt(list_s, SOL_SOCKET, SO_SNDBUF, 
			(char *)&sndsize, sizeof(int));
	sndsize = 1024*1024;
	ret = setsockopt(list_s, SOL_SOCKET, SO_RCVBUF, 
			(char *)&sndsize, sizeof(int));

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(port);

	if ( bind(list_s, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 ) 
	{
		fprintf(stderr, "SERV: Error calling bind()\n");
		exit(-1);
	}

	if ( listen(list_s, LISTENQ) < 0 ) 
	{
		fprintf(stderr, "SERV: Error calling listen()\n");
		exit(-1);
	}

	return list_s;
}

int handle_newclient(int conn_s, int udpsock0);

int handle_clients(int list_s, int udpsock0)
{
	/*int conn_s;
	while ( 1 ) 
	{
		// Wait for a connection, then accept() it
		if ( (conn_s = accept(list_s, NULL, NULL) ) < 0 ) {
			fprintf(stderr, "SERV: Error calling accept()\n");
			exit(-1);
		}


		handle_newclient(conn_s, udpsock0);

		// Close the connected socket
		if ( close(conn_s) < 0 ) {
			fprintf(stderr, "SERV: Error calling close()\n");
			exit(-1);
		}
	}

	return 0;*/

	int conn_s;
	if ( (conn_s = accept(list_s, NULL, NULL) ) < 0 ) {
		fprintf(stderr, "SERV: Error calling accept()\n");
		return -1;
	}
	return conn_s;
}

int setfilename(int fileid, char *tracefile)
{
	if(fileid == 1)
		strcpy(tracefile, "skype-downstream.pcap");
	else if(fileid == 2)
		strcpy(tracefile, "skype-upstream.pcap");
	else if(fileid == 3)
		strcpy(tracefile, "vonage-downstream.pcap");
	else if(fileid == 4)
		strcpy(tracefile, "vonage-upstream.pcap");
	else
		return -1;

	printf("Using tracefile %s.\n", tracefile); fflush(stdout);
	return 0;
}

int preprocess_newclient(int conn_s, int udpsock0, double *capacityup, double *capacitydown, struct sockaddr_in *from, char *tracefile)
{
	int ret = 0;
	pheader hdr;
	pnewclientack pnewack;
	pcapestack pcapack;
	pprobeack ppack;
	pnewclientpacket pnewclient;
	int szhdr = sizeof(struct _header);

	while(1)
	{
		ret = readwrapper(conn_s, (char *)&hdr, szhdr);
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error reading from client: %d\n", conn_s);
			close(conn_s);
			return -1;
		}

		switch(hdr.ptype)
		{
		case P_NEWCLIENT:
			ret = readwrapper(conn_s, 
				(char *)&pnewclient + szhdr, 
				sizeof(struct _newclientpkt) - szhdr);
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error reading from client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			pnewack.compatibilityFlag = 
				(pnewclient.version == VERSION) ? 1 : 0;
			pnewack.header.ptype = P_NEWCLIENT_ACK;
			pnewack.header.length = 0;
			ret = writewrapper(conn_s, (char *)&pnewack, 
					sizeof(struct _newclientack));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error writing to client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			if(pnewack.compatibilityFlag == 0)
			{
				close(conn_s);
				return -1;
			}
			CHKRET(setfilename(pnewclient.fileid, tracefile));
			break;
		case P_CAPEST_START:
			pcapack.header.ptype = P_CAP_ACK;
			pcapack.header.length = 0;
			pcapack.capacity = pcapack.finalflag = 0;
			pcapack.trainlength = TRAIN_LENGTH;
			ret = writewrapper(conn_s, (char *)&pcapack, 
					sizeof(struct _capestack));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error writing to client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			*capacityup = capacityEstimation(conn_s, udpsock0, from);
			*capacitydown = estimateCapacity(conn_s, udpsock0, from);

			return 0;
			break;
		case P_PROBE_START:
			ret = readwrapper(conn_s, (char *)&hdr, 
					sizeof(unsigned int));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error reading from client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}
			ppack.header.ptype = P_PROBE_ACK;
			ppack.header.length = 0;
			ret = writewrapper(conn_s, (char *)&ppack, 
					sizeof(struct _probeack));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error writing to client: %d\n", conn_s);
				close(conn_s);
				return -1;
			}

			return 0;
			break;
		default:
			fprintf(stderr, "unknown packet type!\n");
			close(conn_s);
			return -1;
			break;
		}
	}

	return 0;
}

void printResults(pdiscr_result *respkt)
{
	int i = 0, n = respkt->nresults;

	printf("\nResults:\n--------");
	for(i = 0; i < n; i++)
	{
		printf("\nDelay discrimination:\n");
		if(respkt->results[i].detectability == 0)
		{
			printf("Not detectable.\n");
		}
		else
		{
			if(verbose)
			printf("LIP-P: p-value %f  h %d\n", 
				respkt->results[i].delay_p_lip_p, 
				respkt->results[i].delay_h_lip_p);
			if(respkt->results[i].delay_h_lip_p == 0)
				printf("No delay discrimination detected.\n");
			else
			{
				printf("Delay discrimination detected.\n");
				if(respkt->results[i].delay_diffresult_lip_p 
						== 0)
				printf("Unknown scheduler.\n");
				else if(respkt->results[i].delay_diffresult_lip_p
					       	== 1)
				printf("Application traffic classified high priority: delay between flows: %.2f ms.\n", 
					respkt->results[i].delay_delaydiff_lip_p);
				else if(respkt->results[i].delay_diffresult_lip_p
						== 2)
				printf("Appication traffic classified low priority: delay between flows: %.2f ms.\n", 
					respkt->results[i].delay_delaydiff_lip_p);
			}
			//printf("LIP-A: p-value %f  h %d\n", 
			//respkt.delay_p_lip_a, respkt.delay_h_lip_a);
		}

		printf("\nLoss discrimination:\n");
		if(respkt->results[i].loss_retval_lip_p == -1)
		{
			//printf("Not enough loss samples.\n");
			printf("Not detectable.\n");
		}
		else
		{
			if(verbose)
			printf("LIP-P: p-value %f  h %d\n", 
				respkt->results[i].loss_p_lip_p, 
				respkt->results[i].loss_h_lip_p);
			if(respkt->results[i].loss_h_lip_p == 0)
				printf("No loss discrimination detected.\n");
			else
				printf("Loss discrimination detected.\n");
		}
	}

/*	printf("\nLoss discrimination (overall):\n");
	if(respkt->cum_loss_retval_lip_p == -1)
	{
		printf("LIP-P: not enough loss samples.\n");
	}
	else
	{
		printf("LIP-P: p-value %f  h %d\n", 
				respkt->cum_loss_p_lip_p, 
				respkt->cum_loss_h_lip_p);
	}
*/
}

int getResults(const char *filename, const char *sndfilename, const int probedir, 
		char **env, pdiscr_result *respkt)
{
#ifdef DSERVER
	double p = 1, delaydiff = 0;
	int h = 0, diffresult = 0;
	int ret = 0, i = 0, retval = 0;
	int pl = 0, pt = 0, al = 0, at = 0;
	unsigned int plost = 0, ptotal = 0, alost = 0, atotal = 0;
	extern unsigned int A_targetport;
	extern unsigned int P_targetport;

	respkt->nresults = MAX_NLIPS;
	for(i = 0; i < MAX_NLIPS; i++)
	{
		ret = detectabilityrun(filename, probedir, i, 
				P_targetport, A_targetport, 
				env, &p, &h,
				&diffresult, &delaydiff);
		respkt->results[i].detectability = 
			(h == 1 && diffresult == 1) ? 1 : 0;

		if(respkt->results[i].detectability == 1)
		{
			ret = delayrun(filename, "LIP_P", probedir, i, 
					P_targetport, A_targetport, 
					env, &p, &h,
					&diffresult, &delaydiff);
		}
		respkt->results[i].delay_h_lip_p = h;
		respkt->results[i].delay_p_lip_p = p;
		respkt->results[i].delay_diffresult_lip_p = diffresult;
		respkt->results[i].delay_delaydiff_lip_p = delaydiff;

		/*ret = delayrun(filename, "LIP_A", probedir, env, &p, &h, 
		  &diffresult, &delaydiff);
		  respkt->delay_h_lip_a = h;
		  respkt->delay_p_lip_a = p;
		  respkt->delay_diffresult_lip_a = diffresult;
		  respkt->delay_delaydiff_lip_a = delaydiff;*/

		ret = pairedlossrun(filename, sndfilename, "LIP_P", probedir, i, 
				P_targetport, A_targetport,
				env, &p, &h, &retval, 
				&pl, &pt, &al, &at);
		respkt->results[i].loss_h_lip_p = h;
		respkt->results[i].loss_p_lip_p = p;
		respkt->results[i].loss_retval_lip_p = retval;

		plost += pl;
		ptotal += pt;
		alost += al;
		atotal += at;
	}

	ret = proportiontestrun(plost, ptotal, alost, atotal, env, &p, &h, &retval);
	respkt->cum_loss_h_lip_p = h;
	respkt->cum_loss_p_lip_p = p;
	respkt->cum_loss_retval_lip_p = retval;

	printResults(respkt);
#endif
	return 0;
}

int postprocess_client(int tcpsock, const char *filename, const char *sndfilename,
			const int probedir, char **env)
{
	int ret = 0;
	pheader hdr;
	pdiscr_result respkt;

	while(1)
	{
		ret = readwrapper(tcpsock, (char *)&hdr, 
				sizeof(struct _header));
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error reading from client: %d\n", tcpsock);
			close(tcpsock);
			return -1;
		}

		switch(hdr.ptype)
		{
		case P_DISCR_RESREQ:
			respkt.header.ptype = P_DISCR_RESULT;
			respkt.header.length = 0;

			getResults(filename, sndfilename, probedir, env, &respkt);

			ret = writewrapper(tcpsock, (char *)&respkt, 
				sizeof(struct _header)+2*sizeof(unsigned int)+
				sizeof(int)+sizeof(double)+
				respkt.nresults*sizeof(struct sessionresult));
			if(ret == -1)
			{
				fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
				close(tcpsock);
				return -1;
			}

			return 0;
			break;
		default:
			fprintf(stderr, "unknown packet type!\n");
			close(tcpsock);
			return -1;
			break;
		}
	}

	return 0;
}

inline double timeval_diff(struct timeval x, struct timeval y)
{
	struct timeval result;

	/* Perform the carry for the later subtraction by updating y. */
	if (x.tv_usec < y.tv_usec) 
	{
		int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
		y.tv_usec -= 1000000 * nsec;
		y.tv_sec += nsec;
	}
	if (x.tv_usec - y.tv_usec > 1000000) 
	{
		int nsec = (x.tv_usec - y.tv_usec) / 1000000;
		y.tv_usec += 1000000 * nsec;
		y.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result.tv_sec = x.tv_sec - y.tv_sec;
	result.tv_usec = x.tv_usec - y.tv_usec;

	return result.tv_sec + result.tv_usec/1.0e6;
}

#ifdef _PAIRS_
double capacityEstimation_pairs(int tcpsock)
{
	extern int udpsock0;
	char buf[2000];
	int ret1 = 0, ret2 = 0;
	struct timeval t1, t2, tout;
	double gap = 0;
	double cap = -1, mindcap = -1;
	pcapestack pcapack;
	pcapack.header.ptype = P_CAP_ACK;
	pcapack.header.length = 4;
	int ret = 0;

	int niters = 0, nfound = 0;
	double mindelay1 = 0xFFFFFFFF;
	double mindelay2 = 0xFFFFFFFF;
	double mindelaysum = 0xFFFFFFFF;
	double owd1 = 0, owd2 = 0;
	int mindflag1, mindflag2, mindsumflag;

	fd_set readset;
	int maxfd = (udpsock0 > tcpsock) ? udpsock0+1 : tcpsock+1;

	while(1)
	{
		niters++;
		mindflag1 = mindflag2 = mindsumflag = 0;
		cap = ret1 = ret2 = -1;

		FD_ZERO(&readset);
		FD_SET(udpsock0, &readset);
		tout.tv_sec = 10; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			return -1;
		}
		else if(ret == 0)
		{
			goto noudp;
		}
		if(FD_ISSET(udpsock0, &readset))
		{
			ret1 = recv(udpsock0, buf, 2000, 0);
			if(ret1 == -1)
			{
				fprintf(stderr, "recv error on UDP\n");
				return -1;
			}
			if (ioctl(udpsock0, SIOCGSTAMP, &t1) < 0)
			{
				perror("ioctl-SIOCGSTAMP");
				gettimeofday(&t1,NULL);
			}
			owd1 = fabs(-1e3*(*(double *)buf - (t1.tv_sec + t1.tv_usec/1.0e6)));
			mindflag1 = (mindelay1 > owd1) ? 1 : 0;
			mindelay1 = (mindelay1 > owd1) ? owd1 : mindelay1;
		}

		FD_ZERO(&readset);
		FD_SET(udpsock0, &readset);
		tout.tv_sec = 10; tout.tv_usec = 0;
		ret = select(maxfd, &readset, NULL, NULL, &tout);
		if(ret < 0)
		{
			fprintf(stderr, "select error\n");
			return -1;
		}
		else if(ret == 0)
		{
			goto noudp;
		}
		if(FD_ISSET(udpsock0, &readset))
		{
			ret2 = recv(udpsock0, buf, 2000, 0);
			if(ret2 == -1)
			{
				fprintf(stderr, "recv error on UDP\n");
				return -1;
			}
			if (ioctl(udpsock0, SIOCGSTAMP, &t2) < 0)
			{
				perror("ioctl-SIOCGSTAMP");
				gettimeofday(&t2,NULL);
			}
			owd2 = fabs(-1e3*(*(double *)buf - (t2.tv_sec + t2.tv_usec/1.0e6)));
			mindflag2 = (mindelay2 > owd2) ? 1 : 0;
			mindelay2 = (mindelay2 > owd2) ? owd2 : mindelay2;
		}

		if(ret1 != ret2 || ret1 == -1 || ret2 == -1)
		{
			fprintf(stderr, "sizes %d %d not same OR timeout\n", ret1, ret2);
		}
		else
		{
			//mindsumflag = (mindelaysum > owd1+owd2) ? 1 : 0;
			mindelaysum = (mindelaysum > owd1+owd2) ? owd1+owd2 : mindelaysum;
			mindsumflag = (fabs(owd1+owd2 - (mindelay1+mindelay2)) < 
					0.01/*0.01*(owd1+owd2)*/) ? 1 : 0; //TODO

			gap = timeval_diff(t2, t1); //s
			cap = 1.0e-3*ret1*8.0/gap; //Kbps
			if(mindsumflag) { mindcap = cap; printf("FOUND!\n"); nfound++; }
			printf("cap: %.2f Kbps d1:%f d2:%f sum:%f diff:%f\n", cap, owd1, 
					owd2, mindelaysum,fabs(owd1+owd2 - (mindelay1+mindelay2)));
		}

noudp:
		pcapack.capacity = cap;
		pcapack.finalflag = 0;
		if(niters % 100 == 0 && nfound > 1) { 
			pcapack.finalflag = 1; pcapack.capacity = mindcap; 
		}
		ret = writewrapper(tcpsock, (char *)&pcapack, 
				sizeof(struct _capestack));
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
			close(tcpsock);
			return -1;
		}
		if(pcapack.finalflag == 1) break;
		if(niters > 1000) break;
	}

	return mindcap;
}
#else
double capacityEstimation(int tcpsock, int udpsock0, struct sockaddr_in *from)
{
	char buf[2000];
	int ret1 = 0, sz = 0;
	struct timeval ts, tstart, tend, tout;
	double gap = 0;
	double cap = -1, mediancap = -1;
	pcapestack pcapack;
	pcapack.header.ptype = P_CAP_ACK;
	pcapack.header.length = 0;
	int ret = 0, count = 0, niters = 0;

	fd_set readset;
	int maxfd = (udpsock0 > tcpsock) ? udpsock0+1 : tcpsock+1;

	double caps[10*NITERATIONS], validcaps[10*NITERATIONS];
	memset(caps, 0, 10*NITERATIONS*sizeof(double));
	memset(validcaps, 0, 10*NITERATIONS*sizeof(double));
	int validsz = 0;

	while(1)
	{
		niters++;
		cap = ret1 = sz = -1;
		tstart.tv_sec = tstart.tv_usec = tend.tv_sec = tend.tv_usec = -1;

		for(count = 0; count < TRAIN_LENGTH; count++)
		{
			FD_ZERO(&readset);
			FD_SET(udpsock0, &readset);
			tout.tv_sec = 5; tout.tv_usec = 0;
			ret = select(maxfd, &readset, NULL, NULL, &tout);
			if(ret < 0)
			{
				fprintf(stderr, "select error\n");
				return -1;
			}
			else if(ret == 0)
			{
				break;
			}
			if(FD_ISSET(udpsock0, &readset))
			{
				unsigned int fromlen = sizeof(struct sockaddr_in);
				ret1 = recvfrom(udpsock0, buf, 2000, 0, 
						(struct sockaddr *)from, &fromlen);
				if(ret1 == -1)
				{
					fprintf(stderr, "recv error on UDP\n");
					return -1;
				}
				if (ioctl(udpsock0, SIOCGSTAMP, &ts) < 0)
				{
					perror("ioctl-SIOCGSTAMP");
					gettimeofday(&ts,NULL);
				}
				if(tstart.tv_sec == -1) tstart = ts;
				tend = ts;
				sz = ret1;
			}
		}

		gap = timeval_diff(tend, tstart); //s
		if(sz != -1 && gap != 0)
		{
			cap = 1.0e-3*(TRAIN_LENGTH-1)*sz*8.0/gap; //Kbps
			//printf("cap: %.2f Kbps\n", cap);
			//printf("."); fflush(stdout);
		}
		caps[niters-1] = cap;

		pcapack.capacity = cap;
		pcapack.finalflag = 0;
		pcapack.trainlength = TRAIN_LENGTH;
		if(niters % NITERATIONS == 0) { 
			pcapack.finalflag = 1;
			break;
		}
		if(niters > 10*NITERATIONS) break;

		ret = writewrapper(tcpsock, (char *)&pcapack, 
				sizeof(struct _capestack));
		if(ret == -1)
		{
			fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
			close(tcpsock);
			return -1;
		}
	}

	for(ret1=0; ret1<10*NITERATIONS; ret1++)
	{
		if(caps[ret1] == -1 || caps[ret1] == 0)
		continue;
		validcaps[validsz] = caps[ret1];
		validsz++;
	}
	int compd(const void *a, const void *b);
	qsort((void *)validcaps, validsz, sizeof(double), compd);
	mediancap = validcaps[(int)floor(validsz/2.0)];

	pcapack.finalflag = 1;
	pcapack.capacity = mediancap;
	ret = writewrapper(tcpsock, (char *)&pcapack, 
			sizeof(struct _capestack));
	if(ret == -1)
	{
		fprintf(stderr, "SERV: error writing to client: %d\n", tcpsock);
		close(tcpsock);
		return -1;
	}

	return mediancap;
}

int compd(const void *a, const void *b)
{
	return ( *(double*)a - *(double*)b );
}
#endif

