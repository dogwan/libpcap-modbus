#ifndef _PKT_H_
#define _PKT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

#include <pcap/pcap.h>

int listAllIfaces();
int captureIface(char* dev, char* filter_expr, int cnt);

//ether header
typedef struct {
  unsigned char byte0;
  unsigned char byte1;
  unsigned char byte2;
  unsigned char byte3;
  unsigned char byte4;
  unsigned char byte5;
} MAC_ADDRESS;

void printMAC(MAC_ADDRESS mac);

typedef struct {
  MAC_ADDRESS dst;
  MAC_ADDRESS src;
  unsigned short ether_type;
} ETHER_HEADER;

void printETHER(ETHER_HEADER* ether);


//ip header struct //dogwan
typedef struct {
  unsigned char byte0;
  unsigned char byte1;
  unsigned char byte2;
  unsigned char byte3;
} IP_ADDRESS;

void printIP(IP_ADDRESS ip);

typedef struct {
  ETHER_HEADER ether;
  unsigned char ip_ver_len;
  unsigned char dsf;
  unsigned short tot_len;
  unsigned short id;
  unsigned short flags;
  unsigned char ttl;
  unsigned char proto;
  unsigned short checksum;
  IP_ADDRESS src;
  IP_ADDRESS dst;
} IP_HEADER;

void printIP_HEADER(IP_HEADER* ipheader);

//tcp header //dogwan
typedef struct{
  unsigned char byte0;
  unsigned char byte1;
  unsigned char byte2;
  unsigned char byte3;
} TCP_NUMBER;

void printTCP(TCP_NUMBER tcp);

typedef struct{
  unsigned short byte0;
  unsigned short byte1;
  unsigned short byte2;
  unsigned short byte3;
  unsigned short byte4;
  unsigned short byte5;
} TCP_OPTIONS;

typedef struct{
  IP_HEADER ip;
  unsigned short src_port;
  unsigned short dst_port;
  TCP_NUMBER seq_num;
  TCP_NUMBER ack_num;
  unsigned char header_len;
  unsigned char flags;
  unsigned short window_size;
  unsigned short checksum;
  unsigned short urgent_point;
  TCP_OPTIONS tcp_options;
} TCP_HEADER;

void printTCP_HEADER(TCP_HEADER* tcpheader);

typedef struct{
  TCP_HEADER tcp;
  unsigned char num1;
  unsigned char num2;
  unsigned char num3;
  unsigned char num4;
  unsigned char num5;
  unsigned char num6;
} MODBUS;

typedef struct{
  TCP_HEADER tcp;
  unsigned char* payload;
} MODBUS2;

void printMODBUS(MODBUS* modbus);
#endif