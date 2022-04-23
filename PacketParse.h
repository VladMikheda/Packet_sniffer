/**
 * Project: Sniffer paketů (Varianta ZETA)
 *
 * File:     PacketParse.h
 * Subject:  IPK 2022
 *
 * @author:  Vladislav Mikheda  xmikhe00
 */

#ifndef IPK_PROJECT2_PACKETPARSE_H
#define IPK_PROJECT2_PACKETPARSE_H

#include <pcap.h>
#include <iostream>
#include <string>
#include <ctime>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <cstring>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#define LEN_TIME_BUFFER 30      //len time buffer for "2021-03-19T18:42:52.362+01:00" + "\0" 28 + 1 + 1 -> 30
#define LEN_ZONE_BUFFER 8       // "+0000" + ":" + "\0" 5 + 2 + 1 ->8
#define LEN_MC_BUFFER   6       // ".012" + "\0" 4 + 1 + 1-> 6
#define LEN_MAC         18      // "RA:ND:OM:MA:CA:DD" + "\0" 17 + 1 -> 18
#define OPCODE_REQUEST  0x0001
#define OPCODE_REPLAY   0x0002
#define LEN_LINE 17
#define COUNT_SYMBOLS_LINE 16
#define MIN_PRINT_ASCII 32
#define MAX_PRINT_ASCII 126
#define LEN_ETHERNET_FRAME 14
#define LEN_WORDS 4
#define LEN_IPv6_HEADER 40
//time zone "PLUS H1H2:M1M2"
//#define POS_PLUS 0
//#define POS_H1 1
//#define POS_H2 2
#define POS_COLON 3
#define POS_M1 4
#define POS_M2 5
#define NOT_CORRECT_POS_M1 3
#define NOT_CORRECT_POS_M2 4
//packet type
#define TCP  0x06
#define UDP  0x11
#define ICMP 0x01
#define ICMPv6 0x3A
#define ARP  0x0806
#define IPv4 0x0800
#define IPv6 0x86DD

#endif //IPK_PROJECT2_PACKETPARSE_H
