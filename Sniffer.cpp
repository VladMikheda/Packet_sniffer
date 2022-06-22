/**
 * Project: Sniffer paketů (Varianta ZETA)
 *
 * File:     Sniffer.cpp
 * Subject:  IPK 2022
 *
 * @author:  Vladislav Mikheda  xmikhe00
 */


#include "Sniffer.h"

/**
 * Class Sniffer
 * The class makes the initial settings to start sniffing:
 * requests an IP and a netmask,
 * opens a handler,
 * creates and installs a filter to filter packets.
 * Then sniff the packets.
 */
class Sniffer {
private:
    ParseArguments parse_arguments;
    pcap_t* handler{};
    bpf_u_int32 ip{};
    bpf_u_int32 netmask{};
    char err_buffer[PCAP_ERRBUF_SIZE] = {0};
public:

    /**
     * An instance of the parser class is passed to the class constructor
     * @param parse_arguments instance of the parser class
     */
    explicit Sniffer(ParseArguments parse_arguments){
        this->parse_arguments = parse_arguments;
    }

    /**
     * The main method in the class,
     * the method calls methods to check and listen for packets
     */
    void start_sniff(){

        //Checking the arguments at which information is displayed and the program ends
        if(check_start_condition() == STOP){
            return;
        }

        //sets Netmask and IP
        if(pcap_lookupnet(this->parse_arguments.getAnInterface(), &ip, &netmask, err_buffer) == -1){
            std::cerr << err_buffer << std::endl;
            exit(ERROR_PCAP_NOT_SET_IP);
        }

        //call method to open the handler
        open_handler(this->parse_arguments.getAnInterface());
        //call method to create and set the filter
        if(set_filter() == STOP){
            pcap_close(this->handler);
            exit(ERROR_PCAP_NOT_SET_FILTER);
        }

        u_char flag = 0;
        if((int)parse_arguments.getNum() > 1){
            flag = 1;
        }
        //the function from the "pcap" library, sniffed the packet and
        // called the method to parse the packet in the ParsePacket class
        pcap_loop(this->handler, (int)parse_arguments.getNum(), ParsePacket::packet_parse , &flag);
        pcap_close(this->handler);
    }

private:
    /**
     * Argument check method --interface and -n if equal to 0
     */
    bool check_start_condition(){
        //if the --interface argument is not specified or is specified without a value,
        // call the method to display all interfaces
        if(!this->parse_arguments.getAnInterface()){
            output_all_interface();
            return STOP;
        }
        //if -n 0 will return the STOP flag to terminate the program
        if(this->parse_arguments.getNum() == 0){
            return STOP;
        }

        return START;
    }

    /**
     * Ьethod opens handler and check link type
     * @param nameInterface
     */
    void open_handler(char *interface_name){
        /*
         * opens handler
         * interface_name is the name of the interface for which the handler will be opened
         * MAX_LEN_PACKED is maximum packet length
         * PROM_MOD put the interface in promiscuous mode
         * TO_MC is the time in milliseconds that specifies how long to wait
         * from the moment the interface receives a packet and this program grabs it from the packet buffer
         */
        this->handler = pcap_open_live(interface_name, MAX_LEN_PACKET, PROM_MOD, TO_MC, err_buffer);
        if(!this->handler){
            std::cerr << err_buffer << std::endl;
            exit(ERROR_PCAP_NOT_OPEN_HANDLER);
        }


        //checks if interface supports LINK TYPE ETHERNET
        if(pcap_datalink(this->handler) != DLT_EN10MB){
            std::cerr << "ERROR: link type is not LINKTYPE_ETHERNET" << std::endl;
            pcap_close(this->handler);
            exit(ERROR_PCAP_LINK_TYPE);
        }
    }

    /**
     * Brings all available interfaces to the standard output
     */
    void output_all_interface(){
        pcap_if_t *interface_list = nullptr;
        //return all interface
        if(pcap_findalldevs(&interface_list, err_buffer) == -1){
            std::cerr << "ERROR: interface lookup error" << std::endl;
            exit(ERROR_PCAP);
        }

        //save pointer to first element in list
        pcap_if_t *interface_ptr = interface_list;
        //print the name of all interfaces to standard output
        while(interface_ptr != nullptr){
            std::cout << interface_ptr->name << std::endl;
            interface_ptr = interface_ptr->next;
        }
        //frees memory
        pcap_freealldevs(interface_list);
    }

    /**
     * collect filter from fragments and set
     * @return STOP if filter not set
     */
    bool set_filter(){

        std::string string_filter;
        std::string port;
        if(parse_arguments.getPort()){
            port = parse_arguments.getPort();
        }
        //flag indicates whether the filter will filter the udp (or/and) tcp packet
        bool flag_UDP_TCP = false;
        //flag indicates whether the filter will filter the ICMP (or/and) ARP packet
        bool flag_ICMP_ARP = false;
        //flag indicates whether the filter will filter packet the port number
        bool flag_PORT = false;

        //add udp filter and if a port is specified, the udp packet will be filtered on that port
        if(parse_arguments.isUdp()){
            string_filter = string_filter + "(udp";

            if(!port.empty()){
                string_filter = string_filter + " and port " + port;
            }

            string_filter = string_filter + ")";
            flag_UDP_TCP = true;
            flag_PORT = true;
        }
        //add tcp filter and if a port is specified, the tcp packet will be filtered on that port
        if(parse_arguments.isTcp()){
            if(flag_UDP_TCP){
                string_filter = string_filter + " or ";
            }
            string_filter = string_filter + "(tcp";

            if(!port.empty()){
                string_filter = string_filter + " and port " + port;
            }

            string_filter = string_filter + ")";
            flag_UDP_TCP = true;
            flag_PORT = true;
        }
        //add icmp filter
        if(parse_arguments.isIcmp()){
            if(flag_UDP_TCP){
                string_filter = string_filter + " or ";
            }
            string_filter = string_filter + "icmp or icmp6";
            flag_ICMP_ARP = true;
        }
        //add arp filter
        if(parse_arguments.isArp()){
            if(flag_UDP_TCP || flag_ICMP_ARP){
                string_filter = string_filter + " or ";
            }
            string_filter = string_filter + "arp";
            flag_ICMP_ARP = true;
        }
        //if only port is given or port and icmp,arp
        if(!port.empty() && !flag_PORT){
            if(!flag_ICMP_ARP){
                string_filter = "(port " + port + " and (udp or tcp))";
                flag_PORT = true;
            }else{
                string_filter = string_filter + " or (port " + port + " and (udp or tcp))";
                flag_PORT = true;
            }
        }

        //if parameters are not set
        if(!flag_UDP_TCP && !flag_ICMP_ARP && !flag_PORT){
            string_filter = "udp or tcp or arp or icmp or icmp6";
        }

        bpf_program filter_comp_struct{};

        //filter compile
        if (pcap_compile(this->handler, &filter_comp_struct, string_filter.c_str(), 0, this->ip) == -1){
            std::cerr << "ERROR: filter not compiled" << std::endl;
            pcap_freecode(&filter_comp_struct);
            return STOP;
        }
        //set filter
        if(pcap_setfilter(this->handler,&filter_comp_struct) == -1){
            std::cerr << "ERROR: failed to set filter" << std::endl;
            pcap_freecode(&filter_comp_struct);
            return STOP;
        }
        //frees memory
        pcap_freecode(&filter_comp_struct);

        return START;
    }

};
