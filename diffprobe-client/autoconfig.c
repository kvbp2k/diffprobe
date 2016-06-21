#include <asm/types.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 8192

struct route_info{
	u_int dstAddr;
	u_int srcAddr;
	u_int gateWay;
	char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId){
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;

	do{
		/* Recieve response from the kernel */
		if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0){
			perror("SOCK READ: ");
			return -1;
		}

		nlHdr = (struct nlmsghdr *)bufPtr;

		/* Check if the header is valid */
		if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
		{
			perror("Error in recieved packet");
			return -1;
		}

		/* Check if the its the last message */
		if(nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		}
		else{
			/* Else move the pointer to buffer appropriately */
			bufPtr += readLen;
			msgLen += readLen;
		}

		/* Check if its a multi part message */
		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			/* return if its not */
			break;
		}
	} while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
	return msgLen;
}

/* For parsing the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	int rtLen;

	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

	/* If the route is not for AF_INET or does not belong to main routing table
	   then return. */
	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
		return;

	/* get the rtattr field */
	rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
	rtLen = RTM_PAYLOAD(nlHdr);
	for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen)){
		switch(rtAttr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
				break;
			case RTA_GATEWAY:
				rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
				break;
			case RTA_PREFSRC:
				rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
				break;
			case RTA_DST:
				rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
				break;
		}
	}
}

int getGatewayAddress(char *dev, unsigned int *gateway)
{
	struct nlmsghdr *nlMsg;
	struct rtmsg *rtMsg;
	struct route_info *rtInfo;
	char msgBuf[BUFSIZE];

	int sock, len, msgSeq = 0;

	/* Create Socket */
	if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
		perror("Socket Creation: ");

	/* Initialize the buffer */
	memset(msgBuf, 0, BUFSIZE);

	/* point the header and the msg structure pointers into the buffer */
	nlMsg = (struct nlmsghdr *)msgBuf;
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

	/* Fill in the nlmsg header*/
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
	nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
	nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

	/* Send the request */
	if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
		printf("Write To Socket Failed...\n");
		return -1;
	}

	/* Read the response */
	if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
		printf("Read From Socket Failed...\n");
		return -1;
	}

	/* Parse and print the response */
	rtInfo = (struct route_info *)malloc(sizeof(struct route_info));
	for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len)){
		struct in_addr dstaddr;
		memset(rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg, rtInfo);
		dstaddr.s_addr = rtInfo->dstAddr;
		if(strstr(dev, rtInfo->ifName) && strstr((char *)inet_ntoa(dstaddr), "0.0.0.0"))
		{
			//sprintf(gateway, (char *)inet_ntoa(rtInfo->gateWay));
			*gateway = rtInfo->gateWay;
			break;
		}
	}

	free(rtInfo);
	close(sock);
	return 0;
}

int getMacAddr(unsigned int ipaddr, char *dev, char *macaddr)
{
	int s;
	struct arpreq areq;
	struct sockaddr_in *sin;
	unsigned char *ptr = NULL;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return -1;
	}

	/* Make the ARP request. */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *) &areq.arp_pa;
	sin->sin_family = AF_INET;

	sin->sin_addr.s_addr = ipaddr;
	sin = (struct sockaddr_in *) &areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;

	strncpy(areq.arp_dev, dev, 15);

	if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
		perror("Error: unable to make ARP request");
		return -1;
	}

	ptr = (unsigned char *)&areq.arp_ha.sa_data;
	sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377), 
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)); 

	close(s);
	return 0;
}

int getLocalIP(char *dev, unsigned int *ip)
{
	struct ifaddrs *myaddrs, *ifa;
	struct sockaddr_in *s4;
	int status;

	status = getifaddrs(&myaddrs);
	if (status != 0)
	{
		perror("getifaddrs");
		return -1;
	}

	status = -1;
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL) continue;
		if ((ifa->ifa_flags & IFF_UP) == 0) continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			s4 = (struct sockaddr_in *)(ifa->ifa_addr);
			if(strstr(ifa->ifa_name, dev))
			{
				*ip = s4->sin_addr.s_addr;
				status = 0;
			}
		}
	}

	freeifaddrs(myaddrs);
	if(status == -1)
	printf("Cannot find IP address for device %s. Please verify device.\n", dev);
	return status;
}

int getLocalMAC(char *dev, char *macaddr)
{
	struct ifreq ifr;
	struct ifreq *IFR;
	struct ifconf ifc;
	char buf[1024];
	int s, i;
	int ok = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s==-1) {
		return -1;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if(ioctl(s, SIOCGIFCONF, &ifc) < 0)
	{
		perror("ioctl error\n");
		return -1;
	}

	IFR = ifc.ifc_req;
	for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++)
	{
		if(strstr(dev, IFR->ifr_name))
		{
			strcpy(ifr.ifr_name, IFR->ifr_name);
			if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) 
			{
				if (! (ifr.ifr_flags & IFF_LOOPBACK))
				{
					if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
					{
						ok = 1;
						break;
					}
				}
			}
		}
	}

	close(s);
	if (ok)
	{
		unsigned char *ptr = (unsigned char *)&ifr.ifr_hwaddr.sa_data;
		//bcopy( ifr.ifr_hwaddr.sa_data, addr, 6);
		sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377), 
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)); 
	}
	else
		return -1;

	return 0;
}

/* For printing the routes.
void printRoute(struct route_info *rtInfo)
{
	char tempBuf[512];

	// Print Destination address
	if(rtInfo->dstAddr != 0)
		strcpy(tempBuf, (char *)inet_ntoa(rtInfo->dstAddr));
	else
		sprintf(tempBuf,"*.*.*.*\t");
	fprintf(stdout,"%s\t", tempBuf);

	// Print Gateway address
	if(rtInfo->gateWay != 0)
		strcpy(tempBuf, (char *)inet_ntoa(rtInfo->gateWay));
	else
		sprintf(tempBuf,"*.*.*.*\t");
	fprintf(stdout,"%s\t", tempBuf);

	// Print Interface Name
	fprintf(stdout,"%s\t", rtInfo->ifName);

	// Print Source address
	if(rtInfo->srcAddr != 0)
		strcpy(tempBuf, (char *)inet_ntoa(rtInfo->srcAddr));
	else
		sprintf(tempBuf,"*.*.*.*\t");
	fprintf(stdout,"%s\n", tempBuf);
}*/

