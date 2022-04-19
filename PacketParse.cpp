#include "PacketParse.h"
#include <pcap.h>
#include <iostream>
#include <string>
#include <ctime>
#include <unistd.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <cstring>
#include <netinet/tcp.h>


class ParsePacket {

private:
    static std::string return_RFC_time(timeval timePacket){

        char time_buf[255];
        char time_zone[8];
        char ms[5];
        struct tm *tm_time =  localtime(&timePacket.tv_sec);

        strftime(time_zone,8,"%z",tm_time);
        time_zone[6] = '\0';
        time_zone[5] = time_zone[4];
        time_zone[4] = time_zone[3];
        time_zone[3] = ':';


        long milliseconds = timePacket.tv_usec / 1000;
        snprintf(ms,5,".%03ld",milliseconds);

        strftime(time_buf,255,"%FT%T",tm_time);
        return std::string(time_buf) + std::string(ms) + std::string (time_zone);

    }

    static std::string mac_parse(u_int8_t* mac){
        const u_int8_t LEN_MAC = sizeof("RA:ND:OM:MA:CA:DD");
        char buffer[LEN_MAC];
        snprintf(buffer,LEN_MAC,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
        return std::string(buffer);
    }

    static void ip4_parse(iphdr *ip4_header, std::string *all_info){
        char ip[INET_ADDRSTRLEN];
        memset(ip,0,INET_ADDRSTRLEN);
        inet_ntop(AF_INET,(const void*)(&ip4_header->saddr),ip, INET_ADDRSTRLEN);
        *all_info = *all_info + "src IP: " + std::string(ip) + "\n";
        memset(ip,0,INET_ADDRSTRLEN);
        inet_ntop(AF_INET,(const void*)(&ip4_header->daddr),ip, INET_ADDRSTRLEN);
        *all_info = *all_info + "dst IP: " + std::string(ip) + "\n";
    }


    static void ip6_parse(ip6_hdr *ip6_header, std::string *all_info){
        char ip[INET6_ADDRSTRLEN];
        memset(ip,0,INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,(const void*)(&ip6_header->ip6_src),ip, INET6_ADDRSTRLEN);
        *all_info = *all_info + "src IP: " + std::string(ip) + "\n";
        memset(ip,0,INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,(const void*)(&ip6_header->ip6_dst),ip, INET6_ADDRSTRLEN);
        *all_info = *all_info + "dst IP: " + std::string(ip) + "\n";
    }

    static void tcp_parse(struct tcphdr *tcp_header, std::string *all_info){
        *all_info = *all_info + "src port: " + std::to_string(ntohs(tcp_header->source)) + "\n";
        *all_info = *all_info + "dst port: " + std::to_string(ntohs(tcp_header->dest)) + "\n";

        
    }

public:
    static void packet_parse(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        std::string all_info;
        struct ether_header *ether_h;
        ether_h = (ether_header*) packet;
        all_info = "timestamp: " + return_RFC_time(header->ts) + "\n";
        all_info = all_info + "src MAC: " + mac_parse(ether_h->ether_shost) + "\n"; //src
        all_info = all_info + "dst MAC: " + mac_parse(ether_h->ether_dhost) + "\n"; //src
        all_info = all_info + "frame length: " + std::to_string(header->len) + " bytes\n"; // add frame len
        printf("%X\n",ntohs(ether_h->ether_type));
        switch(ntohs(ether_h->ether_type)){
            case 0x0800: {
                struct iphdr *ip4_header = (iphdr *) (packet + 14);
                ip4_parse(ip4_header,&all_info);
                int ip4_len = ip4_header->ihl * 4;
                switch (ip4_header->protocol){
                    case 0x06: {
                        //tcp
                        struct tcphdr *tcp_header = (tcphdr *) (packet + 14 + ip4_len);
                        tcp_parse(tcp_header, &all_info);
                        break;
                    }
                    case 0x11: {
                        //udp
                        break;
                    }
                    case 0x01: {
                        //ICMP
                        break;
                    }
                }
                break;
            }
            case 0x86DD: {
                struct ip6_hdr *ip6_header = (ip6_hdr *) (packet + 14);
                ip6_parse(ip6_header,&all_info);
                switch (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                    case 0x06:
                        //tcp
                        break;
                    case 0x11:
                        //udp
                        break;
                    case 0x01:
                        //ICMP
                        break;
                }
                break;
            }
        }

        std::cout << all_info << std::endl;
        int num_row = 0;
        printf("0x%04x: ",num_row);
        char buff_ascii[17];
        memset(buff_ascii,0,17);
        int slider = 0;
        for(; slider < header->len; slider++){
            printf("%02x ",packet[slider]);
            if(int(packet[slider]) < 32 || int(packet[slider]) > 127){
                buff_ascii[slider % 16] = '.';
            }else{
                buff_ascii[slider % 16] = char(packet[slider]);
            }
            if(((slider + 1) % 16) == 0){
                num_row += 16;
                printf(" ");
                printf("%s",buff_ascii);
                memset(buff_ascii,0,17);
                if(slider + 1 != header->len){
                    printf("\n");
                    printf("0x%04x: ",num_row);
                }
            }
        }
        printf("   ");
        while(0 != ((slider + 1) % 16)){
            printf("   ");
            slider++;
        }
        printf(" %s\n",buff_ascii);
//        if(ntohs(ether_h->ether_type) == 0x86DD){
//            struct ip6_hdr *ip6_header = (ip6_hdr*) (packet + 14);
//            std::cout << ntohs(ip6_header->ip6r_type) << std::endl;
//            printf("%X\n",ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
//
//        }
    }
};