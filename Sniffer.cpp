
#include "Sniffer.h"
#include "ParseArguments.cpp"
#include <pcap.h>
#include <iostream>
#include <string>
#include <cstring>

class Sniffer {
private:
    ParseArguments parseArguments;
    pcap_t* handler;
    bpf_u_int32 ip;
    bpf_u_int32 netmask;
public:

    Sniffer(ParseArguments parseArguments){
        this->parseArguments = parseArguments;
    }
    void startSniff(){
        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_lookupnet(this->parseArguments.getAnInterface(), &ip, &netmask, errbuf) == -1){
            exit(112);
        }
        std::cout << this->parseArguments.getAnInterface() << std::endl;
        openInterface(this->parseArguments.getAnInterface());
        setFilter();

    }

private:
    void openInterface(char *nameInterface){
//        outPutAllInterface();
        char errbuf[PCAP_ERRBUF_SIZE];
        this->handler = pcap_open_live(nameInterface, BUFSIZ,1,-1,errbuf);
        if(!this->handler){
            std::cout << errbuf << std::endl;
            exit(112);
            //todo error
        }

        if(pcap_datalink(this->handler) != DLT_EN10MB){
            exit(122);
            //todo error
        }
    }

    void outPutAllInterface(){
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *interfaceList;
        if(pcap_findalldevs(&interfaceList,errbuf) == -1){
            exit(112);
        }
        while(interfaceList != nullptr){
            std::cout << interfaceList->name << std::endl;
            interfaceList = interfaceList->next;
        }

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
            stringFilter = stringFilter + "( udp";

            if(!port.empty()){
                stringFilter = stringFilter  + " and port " + port;
            }

            stringFilter = stringFilter + " )";
            flagUT = true;
            flagP = true;
        }
        if(parseArguments.isTcp()){
            if(flagUT){
                stringFilter = stringFilter + " or";
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
                stringFilter = stringFilter + " or";
            }
            stringFilter = stringFilter + " icmp";
            flagIA = true;
        }
        if(parseArguments.isArp()){
            if(flagUT || flagIA){
                stringFilter = stringFilter + " or";
            }
            stringFilter = stringFilter + " arp";
            flagIA = true;
        }
        if(!port.empty() && !flagP){
            if(!flagIA){
                stringFilter = "port " + port;
            }else{
                stringFilter = stringFilter + "or port " + port;
            }
        }
        if(!flagUT && !flagIA && !flagP){
            stringFilter = "udp or tcp or arp or icmp";
        }
        std::cout << stringFilter << std::endl;
        bpf_program filterCompStruct;


        if (pcap_compile(this->handler,&filterCompStruct, stringFilter.c_str(), 0, this->ip) == -1){
            exit(112);
            //todo error
        }

        if(pcap_setfilter(this->handler,&filterCompStruct) == -1){
            exit(112);
            //todo error
        }

        struct pcap_pkthdr header;

        const u_char *packet;

       while(1){
            packet = pcap_next(this->handler, &header);
            std::cout << header.len << std::endl;
        }
        pcap_close(this->handler);
    }

};
