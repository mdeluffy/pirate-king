#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>  // provide function to create socket
#include <unistd.h> // use for defining miscellaneous symbolic constants and types and declare symbolic function(used for close funtion)
#include"csocket.h"
//<sys/socket.h> makes available a type, socklen_t, which is an unsigned opaque integral type of length of at least 32 bits. To forestall portability problems, it is recommended that applications should not use values larger than 232 - 1.
//The <sys/socket.h> header defines the unsigned integral type sa_family_t.

//The <sys/socket.h> header defines the sockaddr structure that includes at least the following members
#include<arpa/inet.h>//has inet_addr function that converts character to ip address
 
 void ProcessPacket(unsigned char* , int);//function declaration for function that will process the incoming packet
 void print_ip_header(unsigned char* , int);//for extracting ip header
 void print_tcp_packet(unsigned char* , int);//for extracting tcp header
 void print_udp_packet(unsigned char * , int);//for extracting udp header
 void print_icmp_packet(unsigned char* , int);//for extracting icmp header
 void PrintData (unsigned char* , int); // for printing the prcessed information of packet in the log file
 
int sock_raw;//holds the value of socket function for socket creation
FILE *logfile;//use for creating a log file
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;//for counting the number of different packets that are captured
struct sockaddr_in source,dest;//contains information of source and destination socket address
 
int main()
{
    int saddr_size , data_size;//to store size of socket address and size of data
    struct sockaddr saddr;//
    struct in_addr in;//to use s_addr (load with inet_aton())   , it is used to ipv4 numbers and dot notation into binary data in network bytes
     
    unsigned char *buffer = (unsigned char *)malloc(65536); 
    //memory size allocation for buffer
     
    logfile=fopen("log.txt","w");//open log file in write mode
    if(logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    //Creation of raw socket (af_inet - is the adress family, sockraw - type of socket , ipproto_tcp specifies the protocol being used in this case which is tcp )
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);//af_inet refers to addresses from the internet specifically ip address
    if(sock_raw < 0)//for showing  that the socket creation has failed 
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1) //to show that socket is successfully created and is putted on recvfrom loop to recieve packets continously
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);//(socket,buffer,buffer_size,check flag, address (points to sockaddr structure in which sending address is to be stored),length of the sockaddr )
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        // processesing of the recieved  packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}//closing the raw socket
 
void ProcessPacket(unsigned char* buffer, int size)
{
    //extracting  the IP Header part of this packet using predefined library by moving the pointer to the start of the buffer
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly
    {
        case 1:  //for ICMP Protocol
            ++icmp;//increamenting icmp variable if the recieved icmp packet 
            print_icmp_packet(Buffer,Size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;//increamenting igmp variable if the recieved igmp packet
            break;
         
        case 6:  //TCP Protocol
            ++tcp;//increamenting tcp variable if the recieved tcp packet
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;//increamenting tcp variable if the recieved tcp packet
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;//increamenting others variable if the recieved other packets like Arp
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
}//prints the new value of the varibles .initial value is o . increamented value of any variable show that the recieved packet is of that protocol
 
void print_ip_header(unsigned char* Buffer, int Size)//using fprintf writing alll the logs of the recieved packet in the file name logfile
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));//copies the the number of zeros equal to the sizeof(source) at the address &source
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));//copies the the number of zeros equal to the sizeof(dest) to the address &dest
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));//to print the binary up address into numeric ip4 address notation of source  
    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));//to print the binary up address into numeric ip4 address notation of destination
}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
             
    fprintf(logfile,"\n\n--------------------------TCP Packet--------------------------\n");    
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile,"\n");
    fprintf(logfile,"TCP Header\n");
    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile,"\n");
    fprintf(logfile,"                        DATA Dump                         ");
    fprintf(logfile,"\n");
         
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile,"TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
    fprintf(logfile,"\n************************************************");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
     
    fprintf(logfile,"\n\n---------------------------UDP Packet---------------------------\n");
     
    print_ip_header(Buffer,Size);           
     
    fprintf(logfile,"\nUDP Header\n");
    fprintf(logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(logfile,"UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
     
    fprintf(logfile,"\n************************************************");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
             
    fprintf(logfile,"\n\n---------------------------ICMP Packet---------------------------\n");   
     
    print_ip_header(Buffer , Size);
             
    fprintf(logfile,"\n");
         
    fprintf(logfile,"ICMP Header\n");
    fprintf(logfile,"   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11) 
        fprintf(logfile,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        fprintf(logfile,"  (ICMP Echo Reply)\n");
    fprintf(logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile,"\n");
 
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile,"UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof icmph , (Size - sizeof icmph - iph->ihl * 4));
     
    fprintf(logfile,"\n************************************************");
}
 
void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        } 
         
        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces`
             
            fprintf(logfile,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}