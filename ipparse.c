/*

// This is a file for ip parsing functions 
// Written by LZ
// 2023.5.18
// plese watch zhidaoshu Graph 2
// Ethernet for example
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "hfiles/address.h"
#include "hfiles/ipparse.h"



/*
    @returns
     like ipchk returns

*/
int physical_direc_chk(char *pkt_data,char* dev_name){
    unsigned char src_mac[6],dst_mac[6],BUFFER[20];
    memcpy(dst_mac,pkt_data,6);
    memcpy(src_mac,pkt_data+6,6);
    get_mac_address(dev_name,BUFFER);
    if(memcmp(BUFFER,src_mac,6) == 0){
        return 0;
    }
    else if(memcmp(BUFFER,dst_mac,6)==0){
        return 1;
    }
    else {
        //cannot get direction by mac
        switch (ip_direct_check(pkt_data,dev_name))
        {
        case 0:
            return 0;
            break;
        case 1:
            return 1;
        
        case 2:
            return 2;
        
        case 3:
            return 3;
        
        case 4:
            return 4;
        
        case 5:
            return 5;
        
        default:
            return 6;
        }
    }
    //get direction
    return 0;


}


/*
    @returns
    0: ipv4 outbound
    1: ipv4 inbound
    2:ipv6 outbound
    3:ipv6 inbound
    4:ipv4 multicast
    5:ipv6 multicast
    6:cannot judge

*/
int ip_direct_check(char *pkt_data, char *dev_name) {
    char IPV4_BUFFER[20], IPV6_BUFFER[40];  // IPv6 地址需要更大的缓冲区
    get_ip_addresses(dev_name, IPV4_BUFFER, IPV6_BUFFER);
    
    // 获取 IP 头部
    unsigned char* ipheader = pkt_data + 14;
    
    // 检查 IP 版本
    if ((ipheader[0] & 0xF0) == 0x40) {  // IPv4
        uint32_t src_addr, dst_addr;
        memcpy(&src_addr, ipheader + 12, 4);
        memcpy(&dst_addr, ipheader + 16, 4);

        if ((src_addr & 0xF0000000) == 0xE0000000 || 
            (dst_addr & 0xF0000000) == 0xE0000000) {
            printf("IPv4 Multicast packet\n");
            return 4;
        }
        struct in_addr local_ip;
        inet_aton(IPV4_BUFFER, &local_ip);
        uint32_t local_addr = local_ip.s_addr;
        
        if (src_addr == local_addr) {
            
            printf("IPv4 Direction: Outbound\n");
            return 0;
        } else if (dst_addr == local_addr) {
            printf("IPv4 Direction: Inbound\n");
            return 1;
        }
        
    } 
    else if ((ipheader[0] & 0xF0) == 0x60) {  // IPv6

        if (ipheader[8] == 0xFF) {
            printf("IPv6 Multicast packet\n");
            return 5;
        }

        struct in6_addr src_addr, dst_addr, local_addr;
        memcpy(&src_addr, ipheader + 8, 16);   // IPv6 源地址
        memcpy(&dst_addr, ipheader + 24, 16);  // IPv6 目的地址
        
        inet_pton(AF_INET6, IPV6_BUFFER, &local_addr);
        
        if (memcmp(&src_addr, &local_addr, sizeof(struct in6_addr)) == 0) {
            printf("IPv6 Direction: Outbound\n");
            return 2;
        } else if (memcmp(&dst_addr, &local_addr, sizeof(struct in6_addr)) == 0) {
            printf("IPv6 Direction: Inbound\n");
            return 3;
        }
    }

    
    printf("Direction: Transit\n");
    return 6;
}

// int ip_direct_check(char *pkt_data,char * dev_name){
//     char IPV4_BUFFER[20],IPV6_BUFFER[20];
//     get_ip_addresses(dev_name,IPV4_BUFFER,IPV6_BUFFER);
//     unsigned char* ipheader = pkt_data+14;
    
//     uint32_t src_addr, dst_addr;
//     // String format 
//     memcpy(&src_addr,ipheader+12,4);
//     memcpy(&dst_addr,ipheader+16,4);
    
//     struct in_addr local_ip;
//     inet_aton(IPV4_BUFFER, &local_ip);
//     uint32_t local_addr = local_ip.s_addr;
    
//     // 比较IP地址
//     if (src_addr == local_addr) {
//         printf("Direction: Outbound\n");
//         return 0;
//     } else if (dst_addr == local_addr) {
//         printf("Direction: Inbound\n");
//         return 0;
//     }
    
//     printf("Direction: Transit\n");
//     return 2;
    
// }   