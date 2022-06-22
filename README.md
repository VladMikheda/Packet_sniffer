# IPK (projekt 2)

## Popis
Zadáním je naprogramování sniffer paketů, který bude schopen filtrovat a zachycovat pakety.
Filtrace se provádí podle protokolu a portu, které jsou zadány uživatelem.

## Překlad
Pro překlad je navržen Makefile. A pro překlad je nutné využit příkaz:
```
make
```
### Spuštění
```
sudo ./sniffer [-i|--interface arg] {-p arg} {--arp -t|--tcp --icmp} {-n arg}
```

___-i | --interface___  název rozhraní na kterém bude provedena filtrace, když není zadán parametr
vypíši se list rozhraní. Jako parametr k argumentu bude využito cokoliv co jde po argumentu.
Například :"-i -t" jako jméno rozhraní bude použito "-t".  
___-p___  port podle kterého budou filtrovány pakety musí být v rozhraní od 1 do 65535.  
___--arp___  bude filtrovat pouze tcp arp pakety.    
___-t | --tcp___  bude filtrovat pouze tcp pakety.  
___--icmp___  bude filtrovat pouze icmp pakety.  
___-n___  počet paketů které budou zaraženy.  
___-h | --help___  bude vypsána pomocná informace a program skonči.   
Program může být volán bez parametru pro výpis rozhraní.
Parametry je možné kombinovat.

### Příklady
```
sudo ./sniffer -i eth0 -t -u -p 443
```
Na rozhraní _eth0_ snifferu budou poslouchat a zachycovat TCP a UDP pakety podle portu 443.

```
sudo ./sniffer -l lo 
```
Na rozhraní _lo_ budou zachyceny pakety typu TCP,UDP,ICMP,ARP

```
sudo ./sniffer -i eth0  p 443
```
Na rozhraní _eth0_ sniffer budou  poslouchat UDP a TCP pakety  podle portu 443

### Seznam souboru
Main.cpp    
PacketParse.cpp  
PacketParse.h  
ParseArgument.cpp  
ParseArgument.h  
Sniffer.cpp  
Sniffer.H  
README.md    
Makefile    
manual.pdf  
