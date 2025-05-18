#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

#include "hfiles/packethandler.h"
// funcs of analysis diffrent link type


#define IPVERSION_MASK 0xF0
// int main(){
//     //get device
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_if_t *alldev;

//     if(pcap_findalldevs(&alldev,errbuf)==-1)
//         return 1;
//     if (alldev == NULL){
//         printf("No device found\n");
//         return 1;
//     }
//     pcap_t * handle = pcap_open_live(
//         alldev->name,65536,1,1000,errbuf
//     );
//     if (handle == NULL)
//         printf("open failed\n");
//     int dlt = pcap_datalink(handle);
//     char *dlt_name = pcap_datalink_val_to_name(dlt);
//     if(dlt_name)
//         printf("Datalink name : %s\n",dlt_name);

//     Ethernet_packet_handler(handle);
//     pcap_close(handle);
//     pcap_freealldevs(alldev);
//     return 0;

// };


/*

pass the handle
for ipv4 packet
*/
int Ethernet_packet_handler(pcap_t* handle){
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    //use pcap_next_ex to get a packet as a  test
    //replace with pcap_loop later
    int res = pcap_next_ex(handle,&header,&pkt_data);
    if (res != 1){
        printf("Error reading packet %s\n",pcap_geterr(handle));
        return 1;
    }
    printf("Packet length: %d\n",header->len);
    //parse ethernet frame
    //not recommend use pkt_data directly
    //pkt_data += 14;//Ethernet header length 


    //use unsigned !!!!
    unsigned char* ipheader = pkt_data+14;
    //check ipv4 by using the first byte of ip header
    //the first byte of ip header is version and header length
    if (header->len < 34)
    {
        printf("Packet too short for Ethernet + IP header\n");
        return 1;
    }


    if ((ipheader[0] & IPVERSION_MASK) == 0x40){
        printf("IPV4 packet\n");
        printf("Source IP: %d.%d.%d.%d\n",
            ipheader[12],ipheader[13],ipheader[14],ipheader[15]);
        printf("Dest IP: %u.%u.%u.%u\n",
            ipheader[16], ipheader[17], ipheader[18], ipheader[19]);
        return 0;
        }
    //add ipv6 support
    else if ((ipheader[0] & IPVERSION_MASK) == 0x60){
        printf("IPV6 packet\n");
        //parse ipv6 header
        //the first byte of ipv6 header is version and traffic class
        //the second byte of ipv6 header is flow label
        printf("Source IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (ipheader[8]<<8)+ipheader[9],
            (ipheader[10]<<8)+ipheader[11],
            (ipheader[12]<<8)+ipheader[13],
            (ipheader[14]<<8)+ipheader[15],
            (ipheader[16]<<8)+ipheader[17],
            (ipheader[18]<<8)+ipheader[19],
            (ipheader[20]<<8)+ipheader[21],
            (ipheader[22]<<8)+ipheader[23]);
        printf("Dest IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (ipheader[24]<<8)+ipheader[25],
            (ipheader[26]<<8)+ipheader[27],
            (ipheader[28]<<8)+ipheader[29],
            (ipheader[30]<<8)+ipheader[31],
            (ipheader[32]<<8)+ipheader[33],
            (ipheader[34]<<8)+ipheader[35],
            (ipheader[36]<<8)+ipheader[37],
            (ipheader[38]<<8)+ipheader[39]);
        return 0;
    }
    else{
        printf("Not a IPV4 or IPV6 packet\n");
        return 1;
    }
    return 0;

}

int WIFI_packet_handler(pcap_t* handle){
    struct pcap_pkthdr* header;
    char * pkt_data;

    pcap_next_ex(handle,&header,&pkt_data);

    //assert the length of frame head is 24
    if (header->len < 24)
    {
        printf("packet is too short for wifi header\n");
        return 1;
    }

    char *wifi_data = pkt_data+24;

    //check LLC/SNAP
    if (wifi_data[0] == 0xAA && wifi_data[1] == 0xAA && wifi_data[2]
     == 0x03){
        unsigned short type = wifi_data[6]<<8|wifi_data[7];
        if (type == 0x0800){
            printf("IPV4 packet\n");
            printf("Source IP: %d.%d.%d.%d\n",
                wifi_data[14],wifi_data[15],wifi_data[16],wifi_data[17]);
            printf("Dest IP: %u.%u.%u.%u\n",
                wifi_data[18], wifi_data[19], wifi_data[20], wifi_data[21]);
            return 0;
        }
        else if (type == 0x86DD){
            printf("IPV6 packet\n");
            //parse ipv6 header
            //the first byte of ipv6 header is version and traffic class
            //the second byte of ipv6 header is flow label
            printf("Source IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
                (wifi_data[14]<<8)+wifi_data[15],
                (wifi_data[16]<<8)+wifi_data[17],
                (wifi_data[18]<<8)+wifi_data[19],
                (wifi_data[20]<<8)+wifi_data[21],
                (wifi_data[22]<<8)+wifi_data[23],
                (wifi_data[24]<<8)+wifi_data[25],
                (wifi_data[26]<<8)+wifi_data[27],
                (wifi_data[28]<<8)+wifi_data[29]);
            printf("Dest IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
                (wifi_data[30]<<8)+wifi_data[31],
                (wifi_data[32]<<8)+wifi_data[33],
                (wifi_data[34]<<8)+wifi_data[35],
                (wifi_data[36]<<8)+wifi_data[37],
                (wifi_data[38]<<8)+wifi_data[39],
                (wifi_data[40]<<8)+wifi_data[41],
                (wifi_data[42]<<8)+wifi_data[43],
                (wifi_data[44]<<8)+wifi_data[45]);
            return 0;
        }
     }
}

int PFLOG_packet_handler(pcap_t* handle){
    struct pcap_pkthdr* header;
    char * pkt_data;
    int res = pcap_next_ex(handle,&header,&pkt_data);
    if (res != 1){
        printf("Error reading packet %s\n",pcap_geterr(handle));
        return 1;
    }

    //pflog head is 28 bytes
    if (header->len < 24)
    {
        printf("packet is too short for pflog header\n");
        return 1;
    }
    unsigned char *ipheader = pkt_data+4;
    if (ipheader[0]&IPVERSION_MASK == 0x40){
        printf("IPV4 packet\n");
        printf("Source IP: %d.%d.%d.%d\n",
            ipheader[12],ipheader[13],ipheader[14],ipheader[15]);
        printf("Dest IP: %u.%u.%u.%u\n",
            ipheader[16], ipheader[17], ipheader[18], ipheader[19]);
        return 0;
    }
    else if (ipheader[0]&IPVERSION_MASK == 0x60){
        printf("IPV6 packet\n");
        //parse ipv6 header
        //the first byte of ipv6 header is version and traffic class
        //the second byte of ipv6 header is flow label
        printf("Source IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (ipheader[8]<<8)+ipheader[9],
            (ipheader[10]<<8)+ipheader[11],
            (ipheader[12]<<8)+ipheader[13],
            (ipheader[14]<<8)+ipheader[15],
            (ipheader[16]<<8)+ipheader[17],
            (ipheader[18]<<8)+ipheader[19],
            (ipheader[20]<<8)+ipheader[21],
            (ipheader[22]<<8)+ipheader[23]);
        printf("Dest IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (ipheader[24]<<8)+ipheader[25],
            (ipheader[26]<<8)+ipheader[27],
            (ipheader[28]<<8)+ipheader[29],
            (ipheader[30]<<8)+ipheader[31],
            (ipheader[32]<<8)+ipheader[33],
            (ipheader[34]<<8)+ipheader[35],
            (ipheader[36]<<8)+ipheader[37],
            (ipheader[38]<<8)+ipheader[39]);
        return 0;
    }
    else{
        printf("Not a IPV4 or IPV6 packet\n");
        return 1;
    }

}



int RAW_packet_handler(pcap_t* handle){
    struct pcap_pkthdr* header;
    char * pkt_data;
    int res = pcap_next_ex(handle,&header,&pkt_data);
    if (res != 1){
        printf("Error reading packet %s\n",pcap_geterr(handle));
        return 1;
    }
    if (header->len < 20)
    {
        printf("packet is too short for raw header\n");
        return 1;
    }
    char * raw_data = pkt_data;
    if (raw_data[0]&IPVERSION_MASK == 0x40){
        printf("IPV4 packet\n");
        printf("Source IP: %d.%d.%d.%d\n",
            raw_data[12],raw_data[13],raw_data[14],raw_data[15]);
        printf("Dest IP: %u.%u.%u.%u\n",
            raw_data[16], raw_data[17], raw_data[18], raw_data[19]);
        return 0;
    }
    else if (raw_data[0]&IPVERSION_MASK == 0x60){
        printf("IPV6 packet\n");
        //parse ipv6 header
        //the first byte of ipv6 header is version and traffic class
        //the second byte of ipv6 header is flow label
        printf("Source IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (raw_data[8]<<8)+raw_data[9],
            (raw_data[10]<<8)+raw_data[11],
            (raw_data[12]<<8)+raw_data[13],
            (raw_data[14]<<8)+raw_data[15],
            (raw_data[16]<<8)+raw_data[17],
            (raw_data[18]<<8)+raw_data[19],
            (raw_data[20]<<8)+raw_data[21],
            (raw_data[22]<<8)+raw_data[23]);
        printf("Dest IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (raw_data[24]<<8)+raw_data[25],
            (raw_data[26]<<8)+raw_data[27],
            (raw_data[28]<<8)+raw_data[29],
            (raw_data[30]<<8)+raw_data[31],
            (raw_data[32]<<8)+raw_data[33],
            (raw_data[34]<<8)+raw_data[35],
            (raw_data[36]<<8)+raw_data[37],
            (raw_data[38]<<8)+raw_data[39]);
        return 0;
    }
    else{
        printf("Not a IPV4 or IPV6 packet\n");
        return 1;
    }
}

int NFLOG_packet_handler(pcap_t* handle){
    struct pcap_pkthdr* header;
    char * pkt_data;
    int res = pcap_next_ex(handle,&header,&pkt_data);
    if (res != 1){
        printf("Error reading packet %s\n",pcap_geterr(handle));
        return 1;
    }
    if (header->len < 24)
    {
        printf("packet is too short for NFLOG header\n");
        return 1;
    }


    //NFLOG head -> 4bytes ipinformation -> at least 20 bytes
    if (header->len < 24){
        printf("Packet is too short for NFLOG header\n");
        return 1;
    }
    unsigned char * ipheader = pkt_data+4;
    if (ipheader[0]&IPVERSION_MASK == 0x40){
        printf("IPV4 packet\n");
        printf("Source IP: %d.%d.%d.%d\n",
            ipheader[12],ipheader[13],ipheader[14],ipheader[15]);
        printf("Dest IP: %u.%u.%u.%u\n",
            ipheader[16], ipheader[17], ipheader[18], ipheader[19]);
        return 0;
    }
    else if (ipheader[0]&IPVERSION_MASK == 0x60){
        printf("IPV6 packet\n");
        //parse ipv6 header
        //the first byte of ipv6 header is version and traffic class
        //the second byte of ipv6 header is flow label
        printf("Source IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (ipheader[8]<<8)+ipheader[9],
            (ipheader[10]<<8)+ipheader[11],
            (ipheader[12]<<8)+ipheader[13],
            (ipheader[14]<<8)+ipheader[15],
            (ipheader[16]<<8)+ipheader[17],
            (ipheader[18]<<8)+ipheader[19],
            (ipheader[20]<<8)+ipheader[21],
            (ipheader[22]<<8)+ipheader[23]);
        printf("Dest IP: %x:%x:%x:%x:%x:%x:%x:%x\n",
            (ipheader[24]<<8)+ipheader[25],
            (ipheader[26]<<8)+ipheader[27],
            (ipheader[28]<<8)+ipheader[29],
            (ipheader[30]<<8)+ipheader[31],
            (ipheader[32]<<8)+ipheader[33],
            (ipheader[34]<<8)+ipheader[35],
            (ipheader[36]<<8)+ipheader[37],
            (ipheader[38]<<8)+ipheader[39]);
        return 0;
    }
    else{
        printf("Not a IPV4 or IPV6 packet\n");
        return 1;
    }

}