#include "pkt.h"
#include "_cgo_export.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static void handler(u_char* args, struct pcap_pkthdr const* header, u_char const* packet);


//implementation//mac_header
void printMAC(MAC_ADDRESS mac) {
  fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x\n",
    mac.byte0, mac.byte1, mac.byte2,
    mac.byte3, mac.byte4, mac.byte5
  );
}

void printETHER(ETHER_HEADER* ether) {
  printMAC(ether->dst);
  printMAC(ether->src);
  fprintf(stdout, "ether type: %04x\n", htons(ether->ether_type));
}

//ip_header
void printIP(IP_ADDRESS ip) {
  fprintf(stdout, "%02x:%02x:%02x:%02x\n",
    ip.byte0, ip.byte1, ip.byte2, ip.byte3
  );
}

void printIP_HEADER(IP_HEADER* ipheader) {
  fprintf(stdout, "ip_ver: %x\n", ((ipheader->ip_ver_len) >> 4) & 0x0f);
  fprintf(stdout, "ip_len: %x\n", ((ipheader->ip_ver_len) & 0x0f));
  fprintf(stdout, "dsf: %02x\n", ipheader->dsf);
  fprintf(stdout, "tot_len: %04x\n", htons(ipheader->tot_len));
  fprintf(stdout, "id: %x\n", htons(ipheader->id));
  fprintf(stdout, "flags: %02x\n", (ipheader->flags));
  fprintf(stdout, "Fragment offset: %02x\n", (htons(ipheader->flags)& 0x1fff));
  fprintf(stdout, "ttl: %01x\n", (ipheader->ttl));
  fprintf(stdout, "proto: %02d\n", (ipheader->proto));
  fprintf(stdout, "checksum: %x\n", htons(ipheader->checksum));
  printIP(ipheader->src);
  printIP(ipheader->dst);
}

//tcp_header
void printTCP(TCP_NUMBER tcp) {
  fprintf(stdout, "%02x:%02x:%02x:%02x\n",
    tcp.byte0, tcp.byte1, tcp.byte2, tcp.byte3
  );
}

void printTCP_HEADER(TCP_HEADER* tcpheader){
  fprintf(stdout, "src_port: %04x\n", htons(tcpheader->src_port));
  fprintf(stdout, "dst_port: %04x\n", htons(tcpheader->dst_port));
  printTCP(tcpheader->seq_num);
  printTCP(tcpheader->ack_num);
  fprintf(stdout, "tcp_header_len: %x\n", ((tcpheader->header_len) >> 4) & 0xff);
  fprintf(stdout, "tcp_flags: %03x\n", tcpheader->flags);
  fprintf(stdout, "window_size: %x\n", tcpheader->window_size);
  fprintf(stdout, "checksum: %x\n", htons(tcpheader->checksum));
  fprintf(stdout, "urgent_point: %04x\n", tcpheader->urgent_point);
}

//modbus
void printMODBUS(MODBUS* modbus){
  fprintf(stdout, "%02x", (modbus->num1));
  fprintf(stdout, " %02x", (modbus->num2));
  fprintf(stdout, " %02x", (modbus->num3));
  fprintf(stdout, " %02x", (modbus->num4));
  fprintf(stdout, " %02x", (modbus->num5));
  fprintf(stdout, " %02x\n", (modbus->num6));
  printf("\n");
}

MODBUS2 NewModbus(int length) {
  MODBUS2 modbus;
  modbus.payload = (unsigned char*)malloc(length);

  return modbus;
}

int listAllIfaces() {
  pcap_if_t* devices;
  char errbuf[PCAP_ERRBUF_SIZE];

  int status = pcap_findalldevs(&devices, errbuf);
  if (status < 0) {
    fprintf(stdout, "%s\n", errbuf);
    return status;
  }
  // Linked List
  for(pcap_if_t* dev = devices; dev != NULL; dev = dev->next) {

    if (dev->flags & PCAP_IF_LOOPBACK) {
      fprintf(stdout, "*%s\n", dev->name);
    } else {
      fprintf(stdout, "%s\n", dev->name);
    }   
  }

  pcap_freealldevs(devices);

  return 0;
}

int captureIface(char* device, char* filter_expr, int cnt) {

  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stdout, "Couldn't open device: %s: %s\n", device, errbuf);
    return -1;
  }

  struct bpf_program filter;

  if (pcap_compile(handle, &filter, filter_expr, 0, 0) < 0) {
    fprintf(stderr, "Could not parse filter expression: %s: %s\n", filter_expr, pcap_geterr(handle));
    return -1;
  }

  if (pcap_setfilter(handle, &filter) < 0) {
    fprintf(stderr, "Could not install filter %s: %s\n", filter_expr, pcap_geterr(handle));
    return -1;
  }

  pcap_loop(handle, cnt, handler, NULL);
  return -1;
}

static void handler(u_char* args, struct pcap_pkthdr const* header, u_char const* packet) {
  ETHER_HEADER* ether = (ETHER_HEADER*)packet;
  IP_HEADER* ipheader = (IP_HEADER*)packet;
  TCP_HEADER* tcpheader = (TCP_HEADER*)packet;
  MODBUS* modbus = (MODBUS*)packet;

  if((modbus->num1)==0x00 && (modbus->num2)>=0x00
      && (modbus->num3)==0x00 && (modbus->num4)==0x00
        && (modbus->num5)==0x00 && (modbus->num6)>=0x01){
  printf("Modbus : ");
  //printETHER(ether);
  //printIP_HEADER(ipheader);
  //printTCP_HEADER(tcpheader);
  //printMODBUS(modbus);

    int modbus_payload_len = header->len - (sizeof(TCP_HEADER));
    int offset = sizeof(TCP_HEADER);
    MODBUS2 m = NewModbus(modbus_payload_len);
    memcpy(m.payload, packet + offset, modbus_payload_len);

    for(int i=0; i<modbus_payload_len; i++) {
      fprintf(stdout, "%02x ", m.payload[i]);
    }
    puts("");
  }
  //int head_len = (((tcpheader->header_len) >> 4) & 0x0f);
  //int option_len = (head_len*4)-20;
  //printf("%d\n",option_len);
  
  // HandlerWrap((void*)packet, header->len);

}