
#include "Main.h"
#include "Sniffer.cpp"

int main(int argc, char **argv){
    ParseArguments a = ParseArguments();
    a.startParse(argc, argv);
    Sniffer sniffer = Sniffer(a);
    sniffer.startSniff();

}

