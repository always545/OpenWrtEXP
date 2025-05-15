#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "address.h"

/*
    @param
         ifname: device name
    @param
         Buffer : buffer to store MAC address
    @return 
        None
    @brief
    A function to get the Mac address of a network interface.
*/
void get_mac_address(const char *ifname,char *Buffer) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        snprintf(Buffer, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        perror("ioctl");
    }
    close(fd);
}

/*
    @param
        ifname: device name

    @param
        IPV4/6Buffer : Buffer to store IPV4 address,default NULL
    
    @return 
        None
    
    @brief
    A function to get the IP address of a network interface.
    by using pointer IPV4Buffer and IPV6Buffer
    @note
        IPV4Buffer and IPV6Buffer should be allocated with enough size
        to store the IP address.
*/
void get_ip_addresses(const char *ifname, char *IPV4Buffer,char *IPV6Buffer) {
    struct ifaddrs *ifaddr, *ifa;
    char addr[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr));
            printf("IPv4: %s\n", addr);
            sprintf(IPV4Buffer, "%s", addr);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, addr, sizeof(addr));
            printf("IPv6: %s\n", addr);
            sprintf(IPV6Buffer, "%s", addr);
        }
    }
    freeifaddrs(ifaddr);
}

// int main(int argc, char *argv[]) {
//     const char *ifname = "eth0";
//     if (argc > 1) ifname = argv[1];
//     char mac[18], ipv4[INET_ADDRSTRLEN], ipv6[INET6_ADDRSTRLEN];
//     printf("Interface: %s\n", ifname);
//     get_mac_address(ifname,mac);
//     get_ip_addresses(ifname,ipv4,ipv6);
//     printf("MAC Address: %s\n", mac);
//     printf("IPv4 Address: %s\n", ipv4);
//     printf("IPv6 Address: %s\n", ipv6);

//     return 0;
// }