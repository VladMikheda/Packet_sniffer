/**
 * Project: Sniffer paketů (Varianta ZETA)
 *
 * File:     Sniffer.h
 * Subject:  IPK 2022
 *
 * @author:  Vladislav Mikheda  xmikhe00
 */

#ifndef IPK_PROJECT2_SNIFFER_H
#define IPK_PROJECT2_SNIFFER_H


#include "ParseArguments.cpp"
#include "PacketParse.cpp"
#include <pcap/pcap.h>
#include <iostream>
#include <string>
#define ERROR_PCAP 12
#define ERROR_PCAP_NOT_SET_IP 13
#define ERROR_PCAP_NOT_SET_FILTER 14
#define ERROR_PCAP_NOT_OPEN_HANDLER 15
#define ERROR_PCAP_LINK_TYPE 16
#define MAX_LEN_PACKET 65535
#define TO_MC 100
#define PROM_MOD 1
#define START true
#define STOP false

#endif //IPK_PROJECT2_SNIFFER_H
