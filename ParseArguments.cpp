

#include <getopt.h>
#include <iostream>


class ParseArguments {


private:
    char *interface = nullptr;
    char *port = nullptr;
    bool tcp = false;
    bool udp = false;
    bool icmp = false;
    bool arp = false;
    unsigned int num = 1;


    void help(){
        printf("help");
    }

public:

    void startParse(int argc, char **argv){

        const char* const shortOpt = "ti:p:n:u::";
//        const char* const shortOpt = "t";
        int index = 0;
        const option longOpts[] = {
                {"arp",0, &index, 0},
                {"icmp",0, &index, 1},
                {"interface",1, nullptr,'i'},
                {"tcp",0, nullptr,'t'},
                {"udp",0, nullptr,'u'},
                {nullptr, 1, nullptr,'p'},
                {nullptr,1, nullptr, 'n'},
                {0,0,0,0}
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
                    this->interface = optarg;
                    break;
                case 'p':
                    this->port = optarg;
                    break;
                case 't':
                    this->tcp = true;
                    break;
                case 'u':
                    this->udp = true;
                    break;
                case 'n':
                    this->num = std::stoi(optarg, nullptr, 10);
                    //todo error
                    break;
                default:
                    help();
                    exit(0);
                    //todo error
                    break;
            }
        }
    }


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
