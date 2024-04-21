# Sniffer paketů

## Popis
Je to sniffer paketů, který bude schopen filtrovat a zachycovat pakety.
Filtrace se provádí podle protokolu a portu, které jsou zadány uživatelem.

## Překlad
#### Pro překlad je navržen Makefile. A pro překlad je nutné využit příkaz:
```
make
```
### Spuštění
```
sudo ./sniffer [-i|--interface arg] {-p arg} {--arp -t|--tcp --icmp} {-n arg}
```
| Parametry | Popis |
|---|---|
|-i / --interface název rozhraní na kterém bude provedena filtrace, když není zadán parametr | vypíši se list rozhraní. Jako parametr k argumentu bude využito cokoliv co jde po argumentu. Například :"-i -t" jako jméno rozhraní bude použito "-t" |  
| -p | port podle kterého budou filtrovány pakety musí být v rozhraní od 1 do 65535 |  
| --arp | bude filtrovat pouze tcp arp pakety |
| -t / --tcp | bude filtrovat pouze tcp pakety |  
| --icmp | bude filtrovat pouze icmp pakety |
| -n | počet paketů které budou zaraženy |
| -h / --help | bude vypsána pomocná informace a program skonči | 

Program může být volán bez parametru pro výpis rozhraní
Parametry je možné kombinova

### Příklady

#### Na rozhraní _eth0_ snifferu budou poslouchat a zachycovat TCP a UDP pakety podle portu 443.
```
sudo ./sniffer -i eth0 -t -u -p 443
```
#### Na rozhraní _lo_ budou zachyceny pakety typu TCP,UDP,ICMP,ARP.
```
sudo ./sniffer -l lo 
```
#### Na rozhraní _eth0_ sniffer budou  poslouchat UDP a TCP pakety  podle portu 443.
```
sudo ./sniffer -i eth0  p 443
```

### Seznam souboru
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
