#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <netinet/in.h>

void get_addresses(const char *ifname) {
    int fd;
    struct ifreq ifr;

    // 获取MAC地址
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        printf("MAC地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    close(fd);

    // 获取IPv4和IPv6地址
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            char addr[INET_ADDRSTRLEN];
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), addr, INET_ADDRSTRLEN);
            printf("IPv4地址: %s\n", addr);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            char addr[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &(sa6->sin6_addr), addr, INET6_ADDRSTRLEN);
            printf("IPv6地址: %s\n", addr);
        }
    }
    freeifaddrs(ifaddr);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("用法: %s <网卡名>\n", argv[0]);
        return 1;
    }
    get_addresses(argv[1]);
    return 0;
}