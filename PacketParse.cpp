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

public:
    static void packet_parse(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        std::string all_info;
        struct ether_header *ether_h;
        ether_h = (ether_header*) packet;
        all_info = "timestamp: " + return_RFC_time(header->ts) + "\n";
        all_info = all_info + "src MAC: " + mac_parse(ether_h->ether_shost) + "\n"; //src
        all_info = all_info + "dst MAC: " + mac_parse(ether_h->ether_dhost) + "\n"; //src
        all_info = all_info + "frame length: " + std::to_string(header->len) + " bytes\n"; // add frame len
        std::cout << all_info << std::endl;
        printf("%X\n",ntohs(ether_h->ether_type));
        if(ntohs(ether_h->ether_type) == 0x86DD){
            struct ip6_hdr *ip6_header = (ip6_hdr*) (packet + 14);
//            std::cout << ntohs(ip6_header->ip6r_type) << std::endl;
            printf("%X\n",ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt);

        }
    }
};