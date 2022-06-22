/**
 * Project: Sniffer paketů (Varianta ZETA)
 *
 * File:     PacketParse.cpp
 * Subject:  IPK 2022
 *
 * @author:  Vladislav Mikheda  xmikhe00
 */

#include "PacketParse.h"

/**
 *The class parses packets
 */
class ParsePacket {

private:
    /**
     * static method, Unix time conversion to RFC3339 format
     * @param timePacket structure with time in seconds and milliseconds
     * @return time to RFC3339 format
     */
    static std::string return_RFC_time(timeval timePacket){

        char time_buf[LEN_TIME_BUFFER];
        char time_zone[LEN_ZONE_BUFFER];
        char ms[LEN_MC_BUFFER];

        memset(time_buf,0,LEN_TIME_BUFFER);
        memset(time_zone,0,LEN_ZONE_BUFFER);
        memset(ms,0,LEN_MC_BUFFER);

        //convert time in seconds to local time
        struct tm *s_tm_time =  localtime(&timePacket.tv_sec);

        //add in buffer time zone
        strftime(time_zone,LEN_ZONE_BUFFER,"%z",s_tm_time);     // "+0000"
        // convert to RFC3339 format   "+H1H2M1M2" -> "+H1H2:M1M2"
        time_zone[POS_M2] = time_zone[NOT_CORRECT_POS_M2];      // "+12344\n"
        time_zone[POS_M1] = time_zone[NOT_CORRECT_POS_M1];      // "+12334\n"
        time_zone[POS_COLON] = ':';                             // "+12:34\n"

        //add milliseconds to time buffer
        long milliseconds = timePacket.tv_usec / 1000;
        snprintf(ms,LEN_MC_BUFFER,".%03ld",milliseconds); // ".012"
        //convert time in seconds to "%Y-%m-%dT%H:%M:%S"
        strftime(time_buf,LEN_TIME_BUFFER,"%FT%T",s_tm_time);
        return std::string(time_buf) + std::string(ms) + std::string (time_zone);

    }
    /**
     * Convert MAC address to ":" format and return it
     * @param mac
     * @return MAC address
     */
    static std::string mac_parse(u_int8_t* mac){
        char buffer[LEN_MAC];
        memset(buffer,0,LEN_MAC);
        snprintf(buffer,LEN_MAC,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
        return buffer;
    }

    /**
     * The method parses IPv4 header and adds to the general string:
     * Time to Live
     * Source IPv4 address
     * Destination IPv4 address
     * @param ip4_header
     * @param all_info
     */
    static void ip4_parse(iphdr *ip4_header, std::string *all_info){
        char ip[INET_ADDRSTRLEN];
        //add information about the lifetime to the general line
        *all_info = *all_info +"Internet Protocol Version 4 (IPv4)\n";
        *all_info = *all_info + "   Time to Live: " + std::to_string(ip4_header->ttl) + "\n";

        memset(ip,0,INET_ADDRSTRLEN);
        //add to ip buffer IPv4 address in dotted decimal format
        inet_ntop(AF_INET,(const void*)(&ip4_header->saddr),ip, INET_ADDRSTRLEN);
        *all_info = *all_info + "   src IP: " + std::string(ip) + "\n";

        memset(ip,0,INET_ADDRSTRLEN);
        //add to ip buffer IPv4 address in dotted decimal format
        inet_ntop(AF_INET,(const void*)(&ip4_header->daddr),ip, INET_ADDRSTRLEN);
        *all_info = *all_info + "   dst IP: " + std::string(ip) + "\n";
    }

    /**
     * The method parses IPv6 header and adds to the general string:
     * Hop Limit
     * Source IPv6 address
     * Destination IPv6 address
     * @param ip6_header
     * @param all_info
     */
    static void ip6_parse(ip6_hdr *ip6_header, std::string *all_info){
        char ip[INET6_ADDRSTRLEN];
        *all_info = *all_info +"Internet Protocol Version 6 (IPv6)\n";
        *all_info = *all_info + "   Hop Limit: " + std::to_string(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim) + "\n";

        memset(ip,0,INET6_ADDRSTRLEN);
        //add to ip buffer IPv6 address in RFC5952 format
        inet_ntop(AF_INET6,(const void*)(&ip6_header->ip6_src),ip, INET6_ADDRSTRLEN);
        *all_info = *all_info + "   src IP: " + std::string(ip) + "\n";

        memset(ip,0,INET6_ADDRSTRLEN);
        //add to ip buffer IPv6 address in RFC5952 format
        inet_ntop(AF_INET6,(const void*)(&ip6_header->ip6_dst),ip, INET6_ADDRSTRLEN);
        *all_info = *all_info + "   dst IP: " + std::string(ip) + "\n";
    }

    /**
     * The method parses TCP header and adds to the general string:
     * Source port
     * Destination port
     * Sequence number
     * Acknowledgment number
     * @param tcp_header
     * @param all_info
     */
    static void tcp_parse(struct tcphdr *tcp_header, std::string *all_info){
        *all_info = *all_info + "Transmission Control Protocol (TCP)\n";
        *all_info = *all_info + "   src port: " + std::to_string(ntohs(tcp_header->source)) + "\n";
        *all_info = *all_info + "   dst port: " + std::to_string(ntohs(tcp_header->dest)) + "\n";
        *all_info = *all_info + "   Sequence number: " + std::to_string(ntohl(tcp_header->seq)) + "\n";
        *all_info = *all_info + "   Acknowledgment number: " + std::to_string(ntohl(tcp_header->ack_seq)) + "\n";

    }

    /**
     * The method parses UDP header and adds to the general string:
     * Source port
     * Destination port
     * @param tcp_header
     * @param all_info
     */
    static void udp_parse(struct udphdr *udp_header, std::string *all_info){
        *all_info = *all_info + "User Datagram Protocol (UDP)\n";
        *all_info = *all_info + "   src port: " + std::to_string(ntohs(udp_header->source)) + "\n";
        *all_info = *all_info + "   dst port: " + std::to_string(ntohs(udp_header->dest)) + "\n";
    }

    /**
     * The method parses ICMP header and adds to the general string:
     * Type
     * Code
     * @param tcp_header
     * @param all_info
     */
    static void icmp_parse(struct icmphdr *icmp_header, std::string * all_info){
        *all_info = *all_info + "Internet Control Message Protocol (ICMP)\n";
        *all_info = *all_info + "   Type " + std::to_string(icmp_header->type) + "\n";
        *all_info = *all_info + "   Code: " + std::to_string(icmp_header->code) + "\n";
    }

    /**
     * The method parses ICMP header and adds to the general string:
     * Type
     * Code
     * @param tcp_header
     * @param all_info
     */
    static void icmp6_parse(struct icmp6_hdr *icmp6_header, std::string * all_info){
        *all_info = *all_info + "Internet Control Message Protocol v6 (ICMPv6)\n";
        *all_info = *all_info + "   Type: " + std::to_string(icmp6_header->icmp6_type) + "\n";
        *all_info = *all_info + "   Code: " + std::to_string(icmp6_header->icmp6_code) + "\n";
    }

    /**
     * The method parses ARP header and adds to the general string:
     * Protocol type
     * Opcode
     * Sender MAC address
     * Sender IP address
     * Target MAC address
     * Target IP address
     * @param tcp_header
     * @param all_info
     */
    static void arp_parse(struct arphdr* arp_header,struct ether_arp* ether_arp_header, std::string * all_info){
        char buffer[LEN_MAC];
        char ip[INET_ADDRSTRLEN];

        *all_info = *all_info + "Address Resolution Protocol (ARP) ";
        std::string opcode;
        opcode = "";

        //add opcode type
        if(ntohs(arp_header->ar_op ) == OPCODE_REQUEST){
            *all_info = *all_info + "(request)\n";
            opcode = "request (1)";
        }else if(ntohs(arp_header->ar_op) == OPCODE_REPLAY){
            *all_info = *all_info + "(reply)\n";
            opcode = "reply (2)";
        }else{
            *all_info = *all_info + "\n";
        }

        //add protocol type
        if(ntohs(arp_header->ar_pro )== IPv4){
            *all_info = *all_info + "   Protocol type IPv4\n";
        }
        *all_info = *all_info + "   Opcode: " + opcode + "\n";

        //add sender MAC and IP address
        memset(buffer,0,LEN_MAC);
        snprintf(buffer,LEN_MAC,"%02x:%02x:%02x:%02x:%02x:%02x", ether_arp_header->arp_sha[0],ether_arp_header->arp_sha[1],
                 ether_arp_header->arp_sha[2],ether_arp_header->arp_sha[3],ether_arp_header->arp_sha[4],ether_arp_header->arp_sha[5]);
        *all_info = *all_info + "   Sender MAC address: " + std::string(buffer) + "\n";

        memset(ip,0,INET_ADDRSTRLEN);
        snprintf(ip,INET_ADDRSTRLEN,"%d.%d.%d.%d", ether_arp_header->arp_spa[0],ether_arp_header->arp_spa[1],
                 ether_arp_header->arp_spa[2],ether_arp_header->arp_spa[3]);
        *all_info = *all_info + "   Sender IP address: " + std::string(ip) + "\n";

        //add target MAC and IP address
        memset(buffer,0,LEN_MAC);
        snprintf(buffer,LEN_MAC,"%02x:%02x:%02x:%02x:%02x:%02x", ether_arp_header->arp_tha[0],ether_arp_header->arp_tha[1],
                 ether_arp_header->arp_tha[2],ether_arp_header->arp_tha[3],ether_arp_header->arp_tha[4],ether_arp_header->arp_tha[5]);
        *all_info = *all_info + "   Target MAC address: " + std::string(buffer) + "\n";

        memset(ip,0,INET_ADDRSTRLEN);
        snprintf(ip,INET_ADDRSTRLEN,"%d.%d.%d.%d", ether_arp_header->arp_tpa[0],ether_arp_header->arp_tpa[1],
                 ether_arp_header->arp_tpa[2],ether_arp_header->arp_tpa[3]);
        *all_info = *all_info + "   Target IP address: " + std::string(ip) + "\n";
    }

    /**
     * The method prints all information to the standard output
     * @param all_info
     * @param header
     * @param packet
     */
    static void out_all(const std::string& all_info, const struct pcap_pkthdr *header, const u_char *packet ){
        //prints information about headers
        std::cout << all_info << std::endl;

        //prints whole packet
        //one line contains 16 bytes of information in hexadecimal format and duplicate in ASCII format
        int num_row = 0;
        char buff_ascii[LEN_LINE];
        memset(buff_ascii,0,LEN_LINE);
        u_int64_t slider = 0;

        printf("0x%04x: ",num_row);
        for(; slider < header->len; slider++){
            //print one byte
            printf("%02x ",packet[slider]);
            //add to ascii buffer symbol
            if(int(packet[slider]) < MIN_PRINT_ASCII || int(packet[slider]) > MAX_PRINT_ASCII){
                buff_ascii[slider % COUNT_SYMBOLS_LINE] = '.';
            }else{
                buff_ascii[slider % COUNT_SYMBOLS_LINE] = char(packet[slider]);
            }
            //if print 16 bytes prints ascii buffer
            if(((slider + 1) % COUNT_SYMBOLS_LINE) == 0){
                num_row += COUNT_SYMBOLS_LINE;
                printf(" ");
                printf("%s",buff_ascii);
                memset(buff_ascii,0,LEN_LINE);
                //if not end packet let's move on next string
                if(slider + 1 != header->len){
                    printf("\n");
                    printf("0x%04x: ",num_row);
                }
            }
        }
        //print missing spaces
        printf("   ");
        while(0 != ((slider + 1) % COUNT_SYMBOLS_LINE)){
            printf("   ");
            slider++;
        }
        //print last ascii string if exist
        printf(" %s\n",buff_ascii);
    }

public:
    /**
     * main packet parsing method
     * @param args
     * @param header
     * @param packet
     */
    static void packet_parse(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        //the flag indicates that more than 1 packet is being read
        static u_char flag = 0;
        //if the flag is 1, the line will be indented so that the data does not merge
        if(flag == 1){
            printf("\n");
        }
        flag= *args;

        std::string all_info; //string for information about headers
        struct ether_header *ether_h; //struct for ethernet frame
        ether_h = (ether_header*) packet;

        //print information
        all_info = "   timestamp: " + return_RFC_time(header->ts) + "\n";
        all_info = all_info + "   src MAC: " + std::string(mac_parse(ether_h->ether_shost)) + "\n"; //src
        all_info = all_info + "   dst MAC: " + std::string(mac_parse(ether_h->ether_dhost)) + "\n"; //dst
        all_info = all_info + "   frame length: " + std::to_string(header->len) + " bytes " +
                "(" + std::to_string(header->len * 8) + " bits)\n"; // add frame len

        //determining the type of package
        switch(ntohs(ether_h->ether_type)){
            case IPv4: {
                all_info = all_info + "   Type: IPv4\n";
                //struct for IPv4 header
                auto *ip4_header = (iphdr *) (packet + LEN_ETHERNET_FRAME);
                //call IPv4 packed parse method
                ip4_parse(ip4_header,&all_info);
                //ip4_len = amount words * 32bits
                int ip4_len = ip4_header->ihl * LEN_WORDS;
                switch (ip4_header->protocol){
                    case TCP: {
                        //struct for TCP header
                        auto *tcp_header = (tcphdr *) (packet + LEN_ETHERNET_FRAME + ip4_len);
                        //call TCP packed parse method
                        tcp_parse(tcp_header, &all_info);
                        break;
                    }
                    case UDP: {
                        //struct for UDP header
                        auto *udp_header = (udphdr *) (packet + LEN_ETHERNET_FRAME + ip4_len);
                        //call UDP packed parse method
                        udp_parse(udp_header, &all_info);
                        break;
                    }
                    case ICMP: {
                        //struct for ICMP header
                        auto *icmp_header = (icmphdr *) (packet + LEN_ETHERNET_FRAME + ip4_len);
                        //call ICMP packed parse method
                        icmp_parse(icmp_header, &all_info);
                        break;
                    }
                }
                break;
            }
            case IPv6: {
                all_info = all_info + "   Type: IPv6\n"; //src
                //struct for IPv6 header
                auto *ip6_header = (ip6_hdr*) (packet + LEN_ETHERNET_FRAME);
                //call IPv6 packed parse method
                ip6_parse(ip6_header,&all_info);
                switch (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                    case TCP: {
                        //struct for TCP header
                        auto *tcp_header = (tcphdr*) (packet + LEN_ETHERNET_FRAME + LEN_IPv6_HEADER);
                        //call TCP packed parse method
                        tcp_parse(tcp_header, &all_info);
                        break;
                    }
                    case UDP: {
                        //struct for UDP header
                        auto *udp_header = (udphdr*) (packet + LEN_ETHERNET_FRAME + LEN_IPv6_HEADER);
                        //call UDP packed parse method
                        udp_parse(udp_header, &all_info);
                        break;
                    }
                    case ICMPv6: {
                        //struct for ICMP header
                        auto *icmp6_header = (icmp6_hdr*) (packet + LEN_ETHERNET_FRAME + LEN_IPv6_HEADER);
                        //call ICMP packed parse method
                        icmp6_parse(icmp6_header, &all_info);
                        break;
                    }
                }
                break;
            }
            case ARP:{
                //struct for ARP header
                auto *arp_header = (arphdr*) (packet + LEN_ETHERNET_FRAME);
                auto *ether_arp_header = (ether_arp*) (packet + LEN_ETHERNET_FRAME);
                //call ICMP packed parse method
                arp_parse(arp_header,ether_arp_header, &all_info);
            }
        }

        //call print all method
        out_all(all_info, header, packet);
    }
};