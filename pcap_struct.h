#ifndef PCAP_STRUCT_H
#define PCAP_STRUCT_H
#include <arpa/inet.h>
#include <netinet/tcp.h>


#define SIZE_ETHERNET 14 //14Bytes Fixed length
#define TCP 6

struct packet_ethernet {
    u_char destMAC[6];
    u_char soceMAC[6];
    u_short ether_type;
    //6+6+u_short(2) = 14 ..?
};

struct packet_ip {
    u_char ip_ver_Hlen; //version || header length..
    u_char ip_tos; //type of service..
    u_short ip_len; //total length
    u_short ip_id; //identification
    u_short ip_offset; // fragment offset
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)		(((ip)->ip_ver_Hlen) & 0x0f)

struct packet_tcp {
    u_int8_t socePort[2];
    u_int8_t destPort[2];
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

#endif // PCAP_STRUCT_H
