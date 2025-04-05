#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];   
    u_char  ether_shost[6];   
    u_short ether_type;        
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;    
    u_short tcp_dport;   
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {  
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

            printf("=====================================\n");
            printf("Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Ethernet Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("IP Src: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("IP Dst: %s\n", inet_ntoa(ip->iph_destip));
            printf("TCP Src Port: %u\n", ntohs(tcp->tcp_sport));
            printf("TCP Dst Port: %u\n", ntohs(tcp->tcp_dport));
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    
    char *dev = "enp0s3";

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Listening for TCP packets on interface: %s\n", dev);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

