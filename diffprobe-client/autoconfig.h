#ifndef _AUTOCONFIG_H_
#define _AUTOCONFIG_H

int getGatewayAddress(char *dev, unsigned int *gateway);
int getMacAddr(unsigned int ipaddr, char *dev, char *macaddr);
int getLocalIP(char *dev, unsigned int *ip);
int getLocalMAC(char *dev, char *macaddr);

#endif

