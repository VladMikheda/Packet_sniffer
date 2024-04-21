# Packet Sniffer


## Description
This is a packet sniffer capable of filtering and capturing packets.
Filtering is done based on the protocol and port specified by the user.

## Compilation
#### PA Makefile is provided for compilation. To compile, use the command:
```
make
```
### Execution
```
sudo ./sniffer [-i|--interface arg] {-p arg} {--arp -t|--tcp --icmp} {-n arg}
```
| Parameters | Description |
|---|---|
|-i / --interface | Specifies the name of the interface on which the filtering will be performed. If no parameter is provided, it will dispaly list the interfaces. Any argument after the parameter will be used as the interface name. For example, "-i -t" will use "-t" as the interface name|  
| -p | pSpecifies the port for packet filtering. The port number must be between 1 and 65535|  
| --arp | Filters only TCP ARP packets|
| -t / --tcp | Filters only TCP packets |  
| --icmp | Filters only ICMP packets |
| -n | Specifies the number of packets to be captured |
| -h / --help | displays usage information and exits the program | 

The program can be called without any parameters to display the interfaces.    
Parameters can be combined.

### Examples

#### Sniffer on interface eth0 capturing TCP and UDP packets on port 443.
```
sudo ./sniffer -i eth0 -t -u -p 443
```
#### Sniffing on interface lo capturing packets of types TCP, UDP, ICMP, and ARP.

```
sudo ./sniffer -i lo 
```
#### Sniffer on interface eth0 capturing UDP and TCP packets on port 443.
```
sudo ./sniffer -i eth0  p 443
```

### File List
- Main.cpp    
- PacketParse.cpp  
- PacketParse.h  
- ParseArgument.cpp  
- ParseArgument.h  
- Sniffer.cpp  
- Sniffer.H  
- README.md    
- Makefile    
- manual.pdf  
