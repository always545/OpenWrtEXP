#include <pcap.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>


typedef struct CALLBACKARGS{
    pcap_if_t *device;
    pcap_t *handle;
} CALLBACKARGS;




volatile sig_atomic_t stop = 0;
void handle_sigint(int sig) {
    stop = 1;
}
/*
how to sum the packet length in different threads? if i dont want store funtion callback in the
main file. use other file to store the callback function instead?
--> use device "any" to capture all packes of all devices

*/

//the callback function which will be called when a packet is captured
void callback(u_char *user,const struct pcap_pkthdr *pkthdr, const u_char *packet){
    //print the device name 
    CALLBACKARGS* args = (CALLBACKARGS*)user;

    printf("Device name: %s\n",args->device->name);
    //print the packet length
    printf("Packet length: %d\n",pkthdr->len);
    //print the packet data
    // for(int i = 0; i < pkthdr->len; i++){
    //     printf("%02x ",packet[i]);
    //     if((i+1)%16 == 0)
    //         printf("\n");
    // }
    // printf("\n");
    // if (stop) {
    //     printf("Stopping capture...\n");
    //     pcap_breakloop(args->handle);
    // }
}


void * package_recv(void* device){
    //open the device
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(((pcap_if_t*)device)->name,65536,1,1000,errbuf);

    //check if the device is opened successfully
    if (handle == NULL)
        {
            printf("Couldn't open device %s: %s\n",((pcap_if_t*)device)->name,errbuf);
            return NULL;
        }

    //build args
    CALLBACKARGS *args = (CALLBACKARGS*)malloc(sizeof(CALLBACKARGS));
    args->device = (pcap_if_t*)device;
    args->handle = handle;
    
    //start capturing
    printf("Listening on %s...\n",((pcap_if_t*)device)->name);
    //never stop until the signal is received
    while(!stop)
        pcap_loop(handle,1,callback,(u_char*) args);
    printf("Jumped out of the loop\n");
    pcap_close(handle);
}




int main(){
    //the error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    //get the device
    pcap_if_t *devices;
    //find all devices  devices will be a linked list
    if (pcap_findalldevs(&devices,errbuf) == -1)
        {
            printf("Error occured while finding devices:%s\n",errbuf);
            return 1;
        }
    if (devices == NULL)
        {
            printf("No devices found.\n");
            return 1;
        }
    //count the number of devices
    int count = 0;
    pcap_if_t *d = devices;
    while (d){
        if(d->name!="any")
            count++;
        d = d->next;
    }
    printf("Number of devices found: %d\n",count);

    //create a thread for each device not any
    pthread_t thread[count];
    count = 0;
    // create thread
    while (devices){
        if(devices->name == "any"){
            devices = devices->next;
            continue;
        }

        if (pthread_create(&thread[count],NULL,package_recv,(void *)devices) != 0)
            {   
                printf("Error creating thread\n");
                return 1;
            }
        printf("Thread %d created for device %s\n",count,devices->name);
        devices = devices->next;
        count++;
    
    }
    //wait
    for (int i = 0; i < 3; i++)
        {   
            printf("round %d\n",i);
            //wait
            for (int j = 0; j < 1000; j++)
                 ;
        }
    handle_sigint(2);
    //wait for all threads to finish
    for (int i = 0; i < count; i++)
        {   printf("Waiting for thread %d to finish\n",i);
            pthread_join(thread[i],NULL);
            printf("Thread %d finished\n",i);
        }
    //free the devices
    pcap_freealldevs(devices);
    return 0;


}