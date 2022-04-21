/**
 * Project: Sniffer paketů (Varianta ZETA)
 *
 * File:     Main.cpp
 * Subject:  IPK 2022
 *
 * @author:  Vladislav Mikheda  xmikhe00
 */

#include "Sniffer.cpp"

/**
 * The main function of the program,
 * creates an instance of the ParseArguments and Sniffer class and launches their main functions
 */
int main(int argc, char **argv){
    ParseArguments a = ParseArguments();
    a.startParse(argc, argv);
    Sniffer sniffer = Sniffer(a);
    sniffer.start_sniff();

}

