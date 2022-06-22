#
# Project: Sniffer paketů (Varianta ZETA)
#
# File:     Makefile
# Subject:  IPK 2022
#
#@author:  Vladislav Mikheda  xmikhe00
#

PROJECT=IPK2022

CC = g++
CFLAGS= -Wall -Wextra -pedantic
FILES=$(wildcard *.cpp)
LIB=-lpcap

all: IPK2022

IPK2022:
	$(CC) $(CFLAGS) $(FILES) -o ipk-sniffer $(LIB)

test:
	./ipk-sniffer

clean:
	rm -f ipk-sniffer