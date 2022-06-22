/**
 * Project: Sniffer paketů (Varianta ZETA)
 *
 * File:     ParseArguments.cpp
 * Subject:  IPK 2022
 *
 * @author:  Vladislav Mikheda  xmikhe00
 */

#include "ParseArguments.h"


/**
 * The class parses the arguments passed to users and checks them
 */
class ParseArguments {

private:
    //arguments
    char *interface = nullptr;
    char *port = nullptr;
    bool tcp = false;
    bool udp = false;
    bool icmp = false;
    bool arp = false;
    unsigned int num = 1; //by default, only one packet will be read.
    //const
    const static int MAX_NUMBER_PORT = 65535;
    const static int MIN_NUMBER_PORT = 1;


    /**
     * The method writes help information to standard output
     */
    static void help(){
        std::cout << "Usage:" << std::endl;
        std::cout << "\t ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp | -t]"
                     "[--udp | -u] [--arp] [--icmp]} {-n num}\n\n" << std::endl;
        std::cout << "-i    --interface        the interface in which it will listen,\n"
                     "                         if the parameter has no value or is not set,\n"
                     "                         a list of all interfaces will be written out\n" << std::endl;

        std::cout << "-p                       port on which packets will be filtered,\n"
                     "                         if the port is not set, packets will not be filtered,\n "
                     "                         сan be from 1 to 65535\n" << std::endl;

        std::cout << "-t    --tcp              only TCP packets will be filtered" << std::endl;
        std::cout << "--udp                    only UDP packets will be filtered" << std::endl;
        std::cout << "--icmp                   only ICMP and ICMPv6 packets will be filtered" << std::endl;
        std::cout << "--arp                    only ARP frame will be filtered" << std::endl;
        std::cout << "-n                       number of packets to filter" << std::endl;
    }

    /**
     * The method checks if the port number is correct
     */
    void port_check(){
        // port number must not contain +
        if(this->port[0] == '+'){
            std::cerr << "ERROR: The port is incorrect or not specified" << std::endl;
            help();
            exit(ERROR_ARGUMENT);
        }
        int port_int;
        try{
            port_int = std::stoi(this->port,nullptr,10);
        }
        catch(std::exception const& e ) {
            std::cerr << "ERROR: The port is incorrect or not specified" << std::endl;
            help();
            exit(ERROR_ARGUMENT);
        }
        if(port_int > MAX_NUMBER_PORT || port_int < MIN_NUMBER_PORT){
            std::cerr << "ERROR: The port is incorrect or not specified" << std::endl;
            help();
            exit(ERROR_ARGUMENT);
        }
    }

    /**
     * the method checks if the number of packets to read is set correctly
     * @param optи user-specified argument
     */
    void num_check(const char* opt){
        try{
            int check_number = std::stoi(opt, nullptr, 10);
            if(check_number < 0) {
                std::cerr << "the -n option is incorrect" << std::endl;
                help();
                exit(ERROR_ARGUMENT);
            }else{
                this->num = check_number;
            }
        }
        catch(std::invalid_argument & e){
            std::cerr << "the -n option is incorrect" << std::endl;
            help();
            exit(ERROR_ARGUMENT);
        }
        catch (std::overflow_error & e){
            std::cerr << "the -n option is incorrect" << std::endl;
            help();
            exit(ERROR_ARGUMENT);
        }
        catch (std::out_of_range & e){
            std::cerr << "the -n option is incorrect" << std::endl;
            help();
            exit(ERROR_ARGUMENT);
        }
    }

public:

    void startParse(int argc, char **argv){

//        const char* const shortOpt = "ti:p:n:u::";
        const char* const shortOpt = "thi:p:n:u";
        int index = 0;
        opterr = 0;
        const option longOpts[] = {
                {"arp",0, &index, 0},
                {"icmp",0, &index, 1},
                {"interface",1, nullptr,'i'},
                {"help",0, nullptr,'h'},
                {"tcp",0, nullptr,'t'},
                {"udp",0, nullptr,'u'},
                {nullptr,0, nullptr,0}
        };
        while(true){
            const auto arg = getopt_long(argc,argv,shortOpt, longOpts, nullptr);
            if(arg == -1){
                break;
            }
            switch (arg) {
                case 0:
                    if(index == 0){
                        this->arp = true;
                    }else if(index == 1){
                        this->icmp = true;
                    }
                    break;
                case'i':
                    if(this->interface){
                        std::cerr << "ERROR: Interface must be set only once" << std::endl;
                        help();
                        exit(ERROR_ARGUMENT);
                    }
                    this->interface = optarg;
                    break;
                case 'p':
                    if(this->port){
                        std::cerr << "ERROR: Port must be set only once" << std::endl;
                        help();
                        exit(ERROR_ARGUMENT);
                    }
                    this->port = optarg;
                    port_check();
                    break;
                case 't':
                    this->tcp = true;
                    break;
                case 'u':
                    this->udp = true;
                    break;
                case 'n':
                    num_check(optarg);
                    break;
                case 'h':
                    help();
                    exit(IT_IS_OK);
                case '?':
                    if(optopt == 'i'){
                        return;
                    }else{
                        help();
                        exit(ERROR_ARGUMENT);
                    }
                    break;
                default:
                    help();
                    exit(ERROR_ARGUMENT);

            }
        }
    }

// getters
    char *getAnInterface() const {
        return interface;
    }

    char *getPort() const {
        return port;
    }

    bool isTcp() const {
        return tcp;
    }

    bool isUdp() const {
        return udp;
    }

    bool isIcmp() const {
        return icmp;
    }

    bool isArp() const {
        return arp;
    }

    unsigned int getNum() const {
        return num;
    }
};
