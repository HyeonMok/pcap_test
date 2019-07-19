#include <pcap.h>
#include <stdio.h>
#include "pcap_struct.h"

const struct packet_ethernet *ethernet;
const struct packet_ip *ip;
const struct packet_tcp *tcp;
const u_char *payload;

u_int size_ip;
u_int size_tcp;
u_int size_payload;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_ether(){
    int i;
    printf("D-MAC: ");
    for(i=0;i<6;i++){
        if(i==5){printf("%02X",ethernet->destMAC[i]); break;}
        printf("%02X-",ethernet->destMAC[i]);
    }printf("     ");

    printf("S-MAC: ");
    for(i=0;i<6;i++){
        if(i==5){printf("%02X\n",ethernet->soceMAC[i]); break;}
        printf("%02X-",ethernet->soceMAC[i]);
    }
}

void print_ip(){
    printf("S-IP: %s",inet_ntoa(ip->ip_src));
    printf("          ");
    printf("D-IP: %s\n",inet_ntoa(ip->ip_dst));

}

void print_tcp(){
    printf("S-PORT: %d",(tcp->socePort[0] << 8 | tcp->socePort[1]));
    printf("                ");
    printf("D-PORT: %d\n",(tcp->destPort[0] << 8 | tcp->destPort[1]));

}

int main(int argc, char* argv[]) {
    if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("────────────────────────────────────────────────────────\n");
    ethernet = (struct packet_ethernet*) packet; //old-style cast......?
    print_ether();
    //non ip -> continue...
    if(ntohs(ethernet->ether_type) != 0x0800){printf("NON IP packet.........\n"); continue;}

    ip = (struct packet_ip*) (packet + SIZE_ETHERNET); //old-style cast......?
    size_ip = IP_HL(ip)*4; //ip size calc
    //printf("%d\n", size_ip); //testcode
    if (size_ip < 20) {continue;}
    print_ip();

    if (ip->ip_p != TCP) {continue;} //pcap_struct.h -> define TCP 6
    tcp = (struct packet_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) { continue;}
    print_tcp();

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - size_ip - size_tcp;

    printf("Payload (10Byte) : ");
    if (size_payload <= 0) { printf(" Not Found..\n"); continue; }
    if (size_payload > 10){ for(int i = 0; i < 10;i++) printf("%02x ",payload[i]);}
    printf("\n");
  }
  pcap_close(handle);
  return 0;
}
