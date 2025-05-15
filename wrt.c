#include <pcap.h>
#include <stdio.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    // 查找所有设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }
    if (alldevs == NULL) {
        printf("No devices found.\n");
        return 1;
    }
    // 打开第一个设备
    pcap_t *handle = pcap_open_live(alldevs->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", alldevs->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    printf("Listening on %s...\n", alldevs->name);
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = pcap_next_ex(handle, &header, &pkt_data);
    // header 不是以太网帧内容，而是描述数据包的元数据（如长度、时间戳等）
    // 以太网帧的实际内容在 pkt_data 指向的内存中
    if (res == 1) {
        printf("Captured a packet with length: %d\n", header->len);
        // 解析以太网帧
        if (header->len >= 34) { // 以太网头14字节 + IP头至少20字节
            const unsigned char *ip_header = pkt_data + 14;
            // 判断是否为IPv4
            if ((ip_header[0] >> 4) == 4) {
                printf("Source IP: %d.%d.%d.%d\n",
                    ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
            } else {
                printf("Not an IPv4 packet.\n");
            }
        } else {
            printf("Packet too short for Ethernet + IP header.\n");
        }
    } else if (res == 0) {
        printf("Timeout expired.\n");
    } else {
        printf("Error reading packet: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}