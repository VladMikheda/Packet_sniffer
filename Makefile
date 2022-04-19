

PROJECT=IPK2022

CC = gcc
CFLAGS=-g -Wall -Wextra -pedantic -std=c++11
LIB=-lpcap
FILES=$(wildcard *.cpp)

all: IPK2022


IPK2022:
	$(CC) $(CFLAGS) $(FILES) -o sniffer $(LIB) -lstdc++
