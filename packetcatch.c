#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

//functions of analysis ip
int Ethernet_packet_handler(pcap_t *handle);
#define IPVERSION_MASK 0xF0
int main(){
    //get device
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldev;

    if(pcap_findalldevs(&alldev,errbuf)==-1)
        return 1;
    if (alldev == NULL){
        printf("No device found\n");
        return 1;
    }
    pcap_t * handle = pcap_open_live(
        alldev->name,65536,1,1000,errbuf
    );
    if (handle == NULL)
        printf("open failed\n");
    int dlt = pcap_datalink(handle);
    char *dlt_name = pcap_datalink_val_to_name(dlt);
    if(dlt_name)
        printf("Datalink name : %s\n",dlt_name);

    Ethernet_packet_handler(handle);
    pcap_close(handle);
    pcap_freealldevs(alldev);
    return 0;

};


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

