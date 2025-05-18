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

int EthernetParse(pcap_t *handle,
    struct pcap_pkthdr header,
    unsigned char* pkt_data    
)
{
    //check the length of data packet
    //Ethernet = 14 + 20++ 
    if (header->len < 34){
        printf("Invalid length for Ethernet Packet %d",header.len);
        return 1
    }
    
    //filter rules?
    struct bpf_program fcode;
    if (pcap_getfilter(handle,&fcode) == 0){
        //used filter
        physical_direc_chk();
    }
    
}

// 判断是否为入站/出站
int check_traffic_direction(unsigned char *local_mac, unsigned char *src_mac) {
    if (memcmp(local_mac, src_mac, 6) == 0) {

        printf("Traffic Direction: Outbound\n");
        return 0;
    } else {
        
        printf("Traffic Direction: Inbound\n");
        return 1;
    }
}


/*
    @returns
    0: physical get direction

    1:failed to get direction

    2:ipget direction
    
    3:multicast

*/
int physical_direc_chk(char *pkt_data){
    unsigned char src_mac[6],dst_mac[6];
    memcpy(dst_mac,pkt_data,6);
    memcpy(src_mac,pkt_data+6,6);
    if (strcmp(dst_mac,src_mac)==0){
        //cannot get direction
        ip_direct_chk(pkt_data)

    }
    //get direction
    return 0;


}