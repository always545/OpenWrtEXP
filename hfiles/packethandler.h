#include <pcap.h>
//functions of analysis Ethernet
int Ethernet_packet_handler(pcap_t *handle);
//functions of analysis WIFI
int WIFI_packet_handler(pcap_t * handle);

//functions of analysis PFLOG
int NFLOG_packet_handler(pcap_t * handle);

int RAW_packet_handler(pcap_t * handle);