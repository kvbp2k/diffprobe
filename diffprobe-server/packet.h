#ifndef _PACKET_H
#define _PACKET_H

enum ptypes
{
	P_NEWCLIENT,
	P_NEWCLIENT_ACK,
	P_CAPEST_START,
	P_CAP_ACK,
	P_TBDETECT_START,
	P_TBDETECT_START_ACK,
	P_TBDETECT_END,
	P_PORTLIST,
	P_PORTLIST_ACK,
	P_SESSION_START,
	P_SESSION_ACK,
	P_PROBE_START,
	P_PROBE_ACK,
	P_PROBE_END,
	P_DISCR_RESREQ,
	P_DISCR_RESULT,
	P_INITREV,
	P_INITREV_ACK,
	P_INITREV_DONE,
	P_INITREV_DONE_ACK,
	P_RECVDATA
};

enum probetypes
{
	BLP_P,
	LIP_P,
	LDP_P,
	BLP_A,
	LIP_A,
	LDP_A,
	BLP_AP,
	LIP_AP,
	LDP_AP
};

enum flow { flowP, flowA };

typedef struct _header
{
	unsigned char ptype;
	unsigned int length;
} __attribute__((packed)) pheader;

typedef struct _newclientpkt
{
	pheader header;
	unsigned int version;
	unsigned int fileid;
} __attribute__((packed)) pnewclientpacket;

typedef struct _newclientack
{
	pheader header;
	unsigned char compatibilityFlag;
} __attribute__((packed)) pnewclientack;

typedef struct _capeststart
{
	pheader header;
} __attribute__((packed)) pcapeststart;

typedef struct _capestack
{
	pheader header;
	double capacity;
	unsigned int finalflag;
	unsigned int trainlength;
} __attribute__((packed)) pcapestack;

typedef struct _tbdetectstart
{
	pheader header;
} __attribute__((packed)) ptbdetectstart;

typedef struct _tbdetectstartack
{
	pheader header;
	unsigned int duration;
} __attribute__((packed)) ptbdetectstartack;

typedef struct _tbdetectend
{
	pheader header;
	unsigned int result;
	unsigned int minbucketDepth;
	unsigned int maxbucketDepth;
	double tokenRate;
	unsigned int abortflag;
} __attribute__((packed)) ptbdetectend;

typedef struct _portlist
{
	pheader header;
	unsigned int p_port;
	unsigned char n_a_ports;
	unsigned int a_port[32];
} __attribute__((packed)) pportlist;

typedef struct _portlistack
{
	pheader header;
	unsigned char status;
} __attribute__((packed)) pportlistack;

typedef struct _sessionstart
{
	pheader header;
} __attribute__((packed)) psessionstart;

typedef struct _sessionack
{
	pheader header;
	unsigned int finalflag;
	double probingrate;
	unsigned char discardflag;
} __attribute__((packed)) psessionack;

typedef struct _probestart
{
	pheader header;
	unsigned int probetype;
} __attribute__((packed)) pprobestart;
typedef struct _probestart pprobeend;

typedef struct _probeack
{
	pheader header;
} __attribute__((packed)) pprobeack;

typedef struct _discr_resreq
{
	pheader header;
} __attribute__((packed)) pdiscr_resreq;

struct sessionresult
{
	unsigned int detectability;
	unsigned int delay_h_lip_p;
	double delay_p_lip_p;
	unsigned int delay_diffresult_lip_p;
	double delay_delaydiff_lip_p;
/*	unsigned int delay_h_lip_a;
	double delay_p_lip_a;
	unsigned int delay_diffresult_lip_a;
	double delay_delaydiff_lip_a;*/
	unsigned int loss_h_lip_p;
	double loss_p_lip_p;
	int loss_retval_lip_p;
} __attribute__((packed)) rsessionresult;
typedef struct _discr_result
{
	pheader header;

	unsigned int cum_loss_h_lip_p;
	double cum_loss_p_lip_p;
	int cum_loss_retval_lip_p;

	unsigned int nresults;
	struct sessionresult results[32];
} __attribute__((packed)) pdiscr_result;

typedef struct _initrev
{
	pheader header;
} __attribute__((packed)) pinitrev;

typedef struct _initrevack
{
	pheader header;
	unsigned int lowport;
	unsigned int highport;
} __attribute__((packed)) pinitrevack;

typedef struct _initrevdone
{
	pheader header;
} __attribute__((packed)) pinitrevdone;

typedef struct _initrevdoneack
{
	pheader header;
} __attribute__((packed)) pinitrevdoneack;

typedef struct _rcvdata
{
	pheader header;
	unsigned int datalength;
} __attribute__((packed)) prcvdata;


int readwrapper(int sock, char *buf, size_t size);
int writewrapper(int sock, char *buf, size_t size);

#endif

