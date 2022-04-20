
#include "Sniffer.h"
#include "ParseArguments.cpp"
#include "PacketParse.cpp"
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

class Sniffer {
private:
    ParseArguments parseArguments;
    pcap_t* handler{};
    bpf_u_int32 ip{};
    bpf_u_int32 netmask{};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
public:

    explicit Sniffer(ParseArguments parseArguments){
        this->parseArguments = parseArguments;
    }
    void startSniff(){
        if(!this->parseArguments.getAnInterface()){
            outPutAllInterface();
            return;
        }

        //наставим маску и ip
        if(pcap_lookupnet(this->parseArguments.getAnInterface(), &ip, &netmask, errbuf) == -1){
            exit(112);
        }
        //open interface
        openHandler(this->parseArguments.getAnInterface());
        setFilter();
//        pcap_loop(this->handler, 1, this->casadasdadll, nullptr);
//        pcap_close(this->handler);
    }

private:
    void openHandler(char *nameInterface){
        this->handler = pcap_open_live(nameInterface, BUFSIZ,1,-1,errbuf);
        if(!this->handler){
            exit(112);
            //todo error
        }

        if(pcap_datalink(this->handler) != DLT_EN10MB){
            exit(122);
            //todo error
        }
    }

    void outPutAllInterface(){
        pcap_if_t *interfaceList = nullptr;
        if(pcap_findalldevs(&interfaceList,errbuf) == -1){
            exit(112);
        }

        pcap_if_t *interface_ptr = interfaceList;
        while(interface_ptr != nullptr){
            std::cout << interface_ptr->name << std::endl;
            interface_ptr = interface_ptr->next;
        }
        interface_ptr = nullptr;
        pcap_freealldevs(interfaceList);
//        //todo ???
//        while(ptr!= nullptr){
//            interfaceList = ptr->next;
//            free(ptr);
//            ptr = interfaceList;
//        }

    }

    void setFilter(){
        std::string stringFilter;
        std::string port;
        if(parseArguments.getPort()){
            port = parseArguments.getPort();
        }
        bool flagUT = false;
        bool flagIA = false;
        bool flagP = false;
        if(parseArguments.isUdp()){
            stringFilter = stringFilter + "(udp";

            if(!port.empty()){
                stringFilter = stringFilter  + " and port " + port;
            }

            stringFilter = stringFilter + ")";
            flagUT = true;
            flagP = true;
        }
        if(parseArguments.isTcp()){
            if(flagUT){
                stringFilter = stringFilter + " or ";
            }
            stringFilter = stringFilter + "(tcp";

            if(!port.empty()){
                stringFilter = stringFilter  + " and port " + port;
            }

            stringFilter = stringFilter + ")";
            flagUT = true;
            flagP = true;
        }
        if(parseArguments.isIcmp()){
            if(flagUT){
                stringFilter = stringFilter + " or ";
            }
            stringFilter = stringFilter + "icmp or icmp6";
            flagIA = true;
        }
        if(parseArguments.isArp()){
            if(flagUT || flagIA){
                stringFilter = stringFilter + " or ";
            }
            stringFilter = stringFilter + "arp";
            flagIA = true;
        }
        if(!port.empty() && !flagP){
            if(!flagIA){
                stringFilter = "port " + port;
                flagP = true;
            }else{
                stringFilter = stringFilter + " or port " + port;
                flagP = true;
            }
        }
        if(!flagUT && !flagIA && !flagP){
            stringFilter = "udp or tcp or arp or icmp or icmp6";
        }
        std::cout << stringFilter << std::endl;
        bpf_program filterCompStruct{};


        if (pcap_compile(this->handler,&filterCompStruct, stringFilter.c_str(), 0, this->ip) == -1){
            exit(112);
            //todo error
        }

        if(pcap_setfilter(this->handler,&filterCompStruct) == -1){
            exit(112);
            //todo error
        }
        pcap_freecode(&filterCompStruct);

        pcap_loop(this->handler, 1, ParsePacket::packet_parse , nullptr);
        pcap_close(this->handler);
    }


//    static std::string returnRFCTime(timeval timePacket){
//
//        char time_buf[255];
//        char time_zone[8];
//        char ms[5];
//        struct tm *tm_time =  localtime(&timePacket.tv_sec);
//
//        strftime(time_zone,8,"%z",tm_time);
//        time_zone[6] = '\0';
//        time_zone[5] = time_zone[4];
//        time_zone[4] = time_zone[3];
//        time_zone[3] = ':';
//
//
//        long milliseconds = timePacket.tv_usec / 1000;
//        snprintf(ms,5,".%03ld",milliseconds);
//
//        strftime(time_buf,255,"%FT%T",tm_time);
//        return std::string(time_buf) + std::string(ms) + std::string (time_zone);
//
//    }
//
//    static void casadasdadll(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
//        std::cout << header->len << std::endl;
//        std::string packet_time = returnRFCTime(header->ts);
//        std::cout << packet_time << std::endl;
//
//        struct ether_header *ether_h;
//        ether_h = (ether_header*) packet;
//        printf("%X\n",ntohs(ether_h->ether_type));
//        if(ntohs(ether_h->ether_type) == 0x86DD){
//            struct ip6_hdr *ip6_header = (ip6_hdr*) (packet + 14);
////            std::cout << ntohs(ip6_header->ip6r_type) << std::endl;
//            printf("%X\n",ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
//
//        }




//    }
};
